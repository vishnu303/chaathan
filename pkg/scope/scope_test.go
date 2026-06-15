package scope

import (
	"testing"

	"github.com/vishnu303/chaathan/pkg/config"
)

func TestScope_IsInScope(t *testing.T) {
	cfg := &config.ScopeConfig{
		InScope:    []string{`^.*\.example\.com$`, `^exact-domain\.org$`},
		OutOfScope: []string{`^exclude\.example\.com$`, `^bad.*\.com$`},
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	tests := []struct {
		target   string
		expected bool
	}{
		{"sub.example.com", true},
		{"exact-domain.org", true},
		{"exclude.example.com", false},
		{"bad-domain.com", false},
		{"google.com", false},
	}

	for _, tc := range tests {
		actual := s.IsInScope(tc.target)
		if actual != tc.expected {
			t.Errorf("IsInScope(%q) = %v, expected %v", tc.target, actual, tc.expected)
		}
	}
}

func TestScope_IsIPExcluded(t *testing.T) {
	cfg := &config.ScopeConfig{
		ExcludeIPs: []string{
			"192.168.1.1",
			"10.0.0.0/24",
		},
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.2", false},
		{"10.0.0.50", true},
		{"10.0.0.255", true},
		{"10.0.1.50", false},
		{"invalid-ip", false},
	}

	for _, tc := range tests {
		actual := s.IsIPExcluded(tc.ip)
		if actual != tc.expected {
			t.Errorf("IsIPExcluded(%q) = %v, expected %v", tc.ip, actual, tc.expected)
		}
	}
}

func TestScope_IsPortAllowed(t *testing.T) {
	cfg := &config.ScopeConfig{
		AllowedPorts: []int{80, 443, 8080},
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	// Allowed
	if !s.IsPortAllowed(80) {
		t.Error("expected port 80 to be allowed")
	}
	if !s.IsPortAllowed(8080) {
		t.Error("expected port 8080 to be allowed")
	}

	// Excluded
	if s.IsPortAllowed(22) {
		t.Error("expected port 22 to be disallowed")
	}

	// Empty allowed ports = all allowed
	emptyCfg := &config.ScopeConfig{}
	emptyScope, _ := New(emptyCfg)
	if !emptyScope.IsPortAllowed(22) {
		t.Error("expected port 22 to be allowed under empty scope config")
	}
}

func TestWildcardScope(t *testing.T) {
	s, err := WildcardScope("example.com")
	if err != nil {
		t.Fatalf("failed to create wildcard scope: %v", err)
	}

	tests := []struct {
		target   string
		expected bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"nested.sub.example.com", true},
		{"notexample.com", false},
		{"example.com.org", false},
	}

	for _, tc := range tests {
		actual := s.IsInScope(tc.target)
		if actual != tc.expected {
			t.Errorf("WildcardScope match(%q) = %v, expected %v", tc.target, actual, tc.expected)
		}
	}
}

func TestScope_FilterDomains(t *testing.T) {
	cfg := &config.ScopeConfig{
		InScope: []string{`^.*\.example\.com$`},
	}

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	input := []string{"sub.example.com", "other.com", "nested.example.com"}
	expected := []string{"sub.example.com", "nested.example.com"}

	actual := s.FilterDomains(input)
	if len(actual) != len(expected) {
		t.Fatalf("FilterDomains returned %v, expected %v", actual, expected)
	}
	for i := range expected {
		if actual[i] != expected[i] {
			t.Errorf("at index %d: expected %q, got %q", i, expected[i], actual[i])
		}
	}
}
