package wildcard_flow_test

import (
	"context"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/runner"
	"github.com/vishnu303/chaathan/pkg/tools"
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
