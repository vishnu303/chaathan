package wildcard_flow

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/runner"
	"github.com/vishnu303/chaathan-flow/pkg/tools"
)

// MockRunner captures the run arguments for validation.
type MockRunner struct {
	LastCmd  string
	LastArgs []string
}

func (m *MockRunner) Run(ctx context.Context, command string, args []string, opts ...runner.Option) (string, error) {
	m.LastCmd = command
	m.LastArgs = args
	return "", nil
}

func TestWafIPCheck(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		// Cloudflare
		{"104.16.5.9", true},
		{"172.64.0.1", true},
		// Fastly
		{"151.101.1.1", true},
		// CloudFront
		{"54.230.15.42", true},
		// Direct/Non-WAF
		{"8.8.8.8", false},
		{"127.0.0.1", false},
		{"203.0.113.80", false},
		{"invalid-ip", false},
	}

	for _, tc := range tests {
		res := isWafIP(tc.ip)
		if res != tc.expected {
			t.Errorf("expected isWafIP(%s) to be %v, got %v", tc.ip, tc.expected, res)
		}
	}
}

func TestCustomAuthPropagation(t *testing.T) {
	mr := &MockRunner{}
	tb := tools.New(mr).WithCustomAuth("PHPSESSID=test_cookie", []string{"Authorization: Bearer test_token", "X-Custom: header"})

	ctx := context.Background()

	// Test Httpx Custom Auth Integration
	_ = tb.RunHttpx(ctx, "in.txt", "out.txt")
	argsJoined := strings.Join(mr.LastArgs, " ")
	if !strings.Contains(argsJoined, "-cookie PHPSESSID=test_cookie") {
		t.Errorf("expected Httpx to receive custom cookie, got: %s", argsJoined)
	}
	if !strings.Contains(argsJoined, "-H Authorization: Bearer test_token") {
		t.Errorf("expected Httpx to receive custom token header, got: %s", argsJoined)
	}
	if !strings.Contains(argsJoined, "-H X-Custom: header") {
		t.Errorf("expected Httpx to receive custom extra header, got: %s", argsJoined)
	}

	// Test Katana Custom Auth Integration
	_ = tb.RunKatana(ctx, "in.txt", "out.txt")
	argsJoined = strings.Join(mr.LastArgs, " ")
	if !strings.Contains(argsJoined, "-H Cookie: PHPSESSID=test_cookie") {
		t.Errorf("expected Katana to receive injected Cookie header, got: %s", argsJoined)
	}
	if !strings.Contains(argsJoined, "-H Authorization: Bearer test_token") {
		t.Errorf("expected Katana to receive custom token header, got: %s", argsJoined)
	}

	// Test ffuf Custom Auth Integration
	_ = tb.RunFfuf(ctx, "http://target.com/FUZZ", "w.txt", "out.txt")
	argsJoined = strings.Join(mr.LastArgs, " ")
	if !strings.Contains(argsJoined, "-b PHPSESSID=test_cookie") {
		t.Errorf("expected ffuf to receive custom cookie, got: %s", argsJoined)
	}
	if !strings.Contains(argsJoined, "-H Authorization: Bearer test_token") {
		t.Errorf("expected ffuf to receive custom token header, got: %s", argsJoined)
	}
}

func TestVulnerabilityEngineCustomAuth(t *testing.T) {
	mr := &MockRunner{}
	tb := tools.New(mr).WithCustomAuth("PHPSESSID=v_cookie", []string{"X-Test-Auth: v_token"})

	scanner, err := tb.GetScanner("nuclei")
	if err != nil {
		t.Fatalf("failed to resolve nuclei scanner: %v", err)
	}

	ctx := context.Background()
	_ = scanner.Scan(ctx, "in.txt", "out.txt", tools.ScanOptions{})

	argsJoined := strings.Join(mr.LastArgs, " ")
	if !strings.Contains(argsJoined, "-H X-Test-Auth: v_token") {
		t.Errorf("expected Nuclei to receive custom auth header, got: %s", argsJoined)
	}
	if !strings.Contains(argsJoined, "-H Cookie: PHPSESSID=v_cookie") {
		t.Errorf("expected Nuclei to receive custom Cookie header, got: %s", argsJoined)
	}
}

func TestVerifyOriginBypassMatch(t *testing.T) {
	// Start a mock HTTP server behaving as an origin server bypass
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if strings.Contains(host, "protected.example.com") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><head><title>Secure Page</title></head><body>Welcome Admin!</body></html>"))
		} else {
			// standard fallback/default IP response
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden: Direct IP access not allowed"))
		}
	}))
	defer server.Close()

	// Extract the test server's raw port/IP
	rawAddr := server.Listener.Addr().String()
	ip, _, err := net.SplitHostPort(rawAddr)
	if err != nil {
		t.Fatalf("failed to parse mock server address: %v", err)
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	// 1. Verify baseline behavior (requesting direct IP with raw IP host header)
	baselineCode, _, err := makeRawRequest(client, server.URL, ip)
	if err != nil {
		t.Fatalf("baseline request failed: %v", err)
	}
	if baselineCode != http.StatusForbidden {
		t.Errorf("expected baseline to return 403 Forbidden, got %d", baselineCode)
	}

	// 2. Verify WAF Bypass behavior (injecting matching Host header)
	probeCode, probeBody, err := makeRawRequest(client, server.URL, "protected.example.com")
	if err != nil {
		t.Fatalf("probe request failed: %v", err)
	}
	if probeCode != http.StatusOK {
		t.Errorf("expected probe to return 200 OK, got %d", probeCode)
	}
	if !strings.Contains(probeBody, "Secure Page") {
		t.Errorf("expected probe body to return the bypassed secure content, got: %s", probeBody)
	}
}
