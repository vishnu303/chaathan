package wildcard_flow

import (
	"strings"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"", 0.0},
		{"aaaaa", 0.0},
		{"abab", 1.0},
	}

	for _, tc := range tests {
		got := shannonEntropy(tc.input)
		if got != tc.expected {
			t.Errorf("shannonEntropy(%q) = %f; want %f", tc.input, got, tc.expected)
		}
	}

	// High entropy string should be > 3.0
	highEntropy := "aBcD1!eFgH2@iJkL"
	got := shannonEntropy(highEntropy)
	if got < 3.0 {
		t.Errorf("shannonEntropy(%q) = %f; want > 3.0", highEntropy, got)
	}
}

func TestIsLikelySecret(t *testing.T) {
	tests := []struct {
		pattern  string
		val      string
		expected bool
	}{
		{"api-keys", "placeholder", false},
		{"api-keys", "your_token", false},
		{"api-keys", "undefined", false},
		{"api-keys", "aaaaaaaaaa", false},
		{"api-keys", "ababababab", false},
		{"api-keys", "aBcD1eFgH2iJkLmN", true}, // high entropy token
		{"slack-webhook", "placeholder", false}, // placeholder check is universal
		{"slack-webhook", "ababababab", true},  // entropy check is only for generic "api-keys"
	}

	for _, tc := range tests {
		got := isLikelySecret(tc.pattern, tc.val)
		if got != tc.expected {
			t.Errorf("isLikelySecret(%q, %q) = %t; want %t", tc.pattern, tc.val, got, tc.expected)
		}
	}
}

func TestExtractContext(t *testing.T) {
	line := "some prefix text here and then the secret token to match followed by suffix text here"
	match := "secret token to match"
	start := strings.Index(line, match)
	end := start + len(match)

	// Test extraction with context size 10
	got := extractContext(line, start, end, 10)
	expected := "...then the secret token to match followed..."
	if got != expected {
		t.Errorf("extractContext(...) = %q; want %q", got, expected)
	}

	// Test boundary at start
	gotStart := extractContext(line, 0, 4, 10) // "some"
	if !strings.HasPrefix(gotStart, "some") || strings.HasPrefix(gotStart, "...") {
		t.Errorf("extractContext(...) for start boundary = %q; did not expect leading ellipsis", gotStart)
	}
}
