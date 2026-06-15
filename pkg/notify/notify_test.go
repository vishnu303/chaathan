package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
)

func TestEscapeMarkdown(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello_world", "hello\\_world"},
		{"hello*world", "hello\\*world"},
		{"back\\slash", "back\\\\slash"},
		{"nested[bracket]test", "nested\\[bracket\\]test"},
	}

	for _, tc := range tests {
		actual := escapeMarkdown(tc.input)
		if actual != tc.expected {
			t.Errorf("escapeMarkdown(%q) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestTitleCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"a", "A"},
		{"hello", "Hello"},
	}

	for _, tc := range tests {
		actual := titleCase(tc.input)
		if actual != tc.expected {
			t.Errorf("titleCase(%q) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input    time.Duration
		expected string
	}{
		{45 * time.Second, "45s"},
		{19*time.Minute + 56*time.Second, "19m 56s"},
		{2 * time.Hour, "2h"},
		{2*time.Hour + 3*time.Minute, "2h 3m"},
	}

	for _, tc := range tests {
		actual := formatDuration(tc.input)
		if actual != tc.expected {
			t.Errorf("formatDuration(%v) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestGetOrderedStatsKeys(t *testing.T) {
	stats := map[string]int{
		"urls":            10,
		"subdomains":      5,
		"vulnerabilities": 1,
		"unknown_metric":  3,
	}

	expected := []string{"subdomains", "urls", "vulnerabilities", "unknown_metric"}
	actual := getOrderedStatsKeys(stats)

	if len(actual) != len(expected) {
		t.Fatalf("expected length %d, got %d", len(expected), len(actual))
	}
	for i := range expected {
		if actual[i] != expected[i] {
			t.Errorf("at index %d: expected %q, got %q", i, expected[i], actual[i])
		}
	}
}

func TestNotifier_SendFinding_Discord(t *testing.T) {
	var receivedPayload map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		err := json.NewDecoder(r.Body).Decode(&receivedPayload)
		if err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.NotificationConfig{
		Enabled:        true,
		MinSeverity:    "high",
		DiscordWebhook: server.URL,
	}

	notifier := New(cfg)

	finding := Finding{
		Target:    "example.com",
		Type:      "vulnerability",
		Name:      "Critical Vulnerability",
		Severity:  "critical",
		Timestamp: time.Now(),
	}

	err := notifier.SendFinding(finding)
	if err != nil {
		t.Fatalf("SendFinding returned error: %v", err)
	}

	if receivedPayload == nil {
		t.Fatal("no payload received by test server")
	}

	embeds, ok := receivedPayload["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatal("no embeds in Discord payload")
	}

	embed := embeds[0].(map[string]any)
	title := embed["title"].(string)
	if !strings.Contains(title, "CRITICAL") || !strings.Contains(title, "Critical Vulnerability") {
		t.Errorf("unexpected title in embed: %s", title)
	}
}
