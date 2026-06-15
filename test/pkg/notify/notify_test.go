package notify_test
 
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/notify"
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
		actual := notify.EscapeMarkdown(tc.input)
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
		actual := notify.TitleCase(tc.input)
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
		actual := notify.FormatDuration(tc.input)
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
	actual := notify.GetOrderedStatsKeys(stats)

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

	notifier := notify.New(cfg)

	finding := notify.Finding{
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

func TestEscapeHTML(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello & world", "hello &amp; world"},
		{"<script>", "&lt;script&gt;"},
		{"\"double-quotes\"", "&#34;double-quotes&#34;"},
		{"'single-quotes'", "&#39;single-quotes&#39;"},
	}

	for _, tc := range tests {
		actual := notify.EscapeHTML(tc.input)
		if actual != tc.expected {
			t.Errorf("EscapeHTML(%q) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestNotifier_SendFinding_Telegram_HTML(t *testing.T) {
	var receivedPayload map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/botmocktoken/sendMessage") {
			t.Errorf("expected URL path to contain bot token, got %s", r.URL.Path)
		}

		err := json.NewDecoder(r.Body).Decode(&receivedPayload)
		if err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notify.SetTelegramAPIURL(server.URL)
	defer notify.SetTelegramAPIURL("https://api.telegram.org")

	cfg := &config.NotificationConfig{
		Enabled:          true,
		MinSeverity:      "low",
		TelegramBotToken: "mocktoken",
		TelegramChatID:   "mockchatid",
	}

	notifier := notify.New(cfg)

	finding := notify.Finding{
		Target:      "testtarget.com",
		Type:        "vulnerability",
		Name:        "SQL Injection",
		Severity:    "critical",
		Description: "A description of SQL injection.",
		Evidence:    "UNION SELECT 1, 2, 3",
		URL:         "https://testtarget.com/sqli?id=1",
		Timestamp:   time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
	}

	err := notifier.SendFinding(finding)
	if err != nil {
		t.Fatalf("SendFinding returned error: %v", err)
	}

	if receivedPayload == nil {
		t.Fatal("no payload received by test server")
	}

	chatID, _ := receivedPayload["chat_id"].(string)
	if chatID != "mockchatid" {
		t.Errorf("expected chat_id 'mockchatid', got %q", chatID)
	}

	parseMode, _ := receivedPayload["parse_mode"].(string)
	if parseMode != "HTML" {
		t.Errorf("expected parse_mode 'HTML', got %q", parseMode)
	}

	text, _ := receivedPayload["text"].(string)
	if !strings.Contains(text, "🔴 <b>CRITICAL Finding: SQL Injection</b>") {
		t.Errorf("missing header in Telegram message: %s", text)
	}
	if !strings.Contains(text, "🎯 <b>Target:</b> <code>testtarget.com</code>") {
		t.Errorf("missing Target in Telegram message: %s", text)
	}
	if !strings.Contains(text, "🐛 <b>Type:</b> <code>vulnerability</code>") {
		t.Errorf("missing Type in Telegram message: %s", text)
	}
	if !strings.Contains(text, "⏰ <b>Detected:</b> <code>2026-06-15 12:00:00 UTC</code>") {
		t.Errorf("missing timestamp in Telegram message: %s", text)
	}
	if !strings.Contains(text, "🔗 <b>URL:</b> <code>https://testtarget.com/sqli?id=1</code>") {
		t.Errorf("missing URL in Telegram message: %s", text)
	}
	if !strings.Contains(text, "<blockquote expandable>") {
		t.Errorf("missing expandable blockquote in Telegram message: %s", text)
	}
	if !strings.Contains(text, "<b>Description:</b>\nA description of SQL injection.") {
		t.Errorf("missing description inside blockquote: %s", text)
	}
	if !strings.Contains(text, "<b>Evidence:</b>\n<pre>UNION SELECT 1, 2, 3</pre>") {
		t.Errorf("missing evidence inside blockquote: %s", text)
	}
}

func TestNotifier_SendScanComplete_Telegram_HTML(t *testing.T) {
	var receivedPayload map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&receivedPayload)
		if err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notify.SetTelegramAPIURL(server.URL)
	defer notify.SetTelegramAPIURL("https://api.telegram.org")

	cfg := &config.NotificationConfig{
		Enabled:          true,
		TelegramBotToken: "mocktoken",
		TelegramChatID:   "mockchatid",
	}

	notifier := notify.New(cfg)

	scan := notify.ScanComplete{
		Target:     "scantarget.com",
		ScanID:     456,
		Duration:   12 * time.Minute,
		Stats:      map[string]int{"subdomains": 12, "vulnerabilities": 2},
		ReportPath: "/tmp/report.html",
	}

	err := notifier.SendScanComplete(scan)
	if err != nil {
		t.Fatalf("SendScanComplete returned error: %v", err)
	}

	text, _ := receivedPayload["text"].(string)
	if !strings.Contains(text, "🏁 <b>Scan Completed Successfully</b>") {
		t.Errorf("missing header in Telegram message: %s", text)
	}
	if !strings.Contains(text, "🎯 <b>Target:</b> <code>scantarget.com</code>") {
		t.Errorf("missing target in Telegram message: %s", text)
	}
	if !strings.Contains(text, "🔢 <b>Scan ID:</b> <code>#456</code>") {
		t.Errorf("missing Scan ID in Telegram message: %s", text)
	}
	if !strings.Contains(text, "🌐 Subdomains: <b>12</b>") {
		t.Errorf("missing subdomains metric in Telegram message: %s", text)
	}
	if !strings.Contains(text, "🚨 Vulnerabilities: <b>2</b>") {
		t.Errorf("missing vulnerabilities metric in Telegram message: %s", text)
	}
	if !strings.Contains(text, "📂 <b>Report:</b> <code>/tmp/report.html</code>") {
		t.Errorf("missing Report path in Telegram message: %s", text)
	}
}

func TestNotifier_SendStepComplete_Telegram_HTML(t *testing.T) {
	var receivedPayload map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&receivedPayload)
		if err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notify.SetTelegramAPIURL(server.URL)
	defer notify.SetTelegramAPIURL("https://api.telegram.org")

	cfg := &config.NotificationConfig{
		Enabled:          true,
		StepComplete:     true,
		TelegramBotToken: "mocktoken",
		TelegramChatID:   "mockchatid",
	}

	notifier := notify.New(cfg)

	step := notify.StepComplete{
		Target:        "steptarget.com",
		ScanID:        789,
		StepName:      "subdomain_recon",
		StepNumber:    2,
		TotalSteps:    10,
		Duration:      15 * time.Second,
		FindingsCount: 3,
		ScanType:      "wildcard",
	}

	err := notifier.SendStepComplete(step)
	if err != nil {
		t.Fatalf("SendStepComplete returned error: %v", err)
	}

	text, _ := receivedPayload["text"].(string)
	if !strings.Contains(text, "✅ <b>Step Completed: subdomain_recon</b>") {
		t.Errorf("missing header in Telegram message: %s", text)
	}
	if !strings.Contains(text, "🎯 <b>Target:</b> <code>steptarget.com</code>") {
		t.Errorf("missing Target in Telegram message: %s", text)
	}
	if !strings.Contains(text, "📊 <b>Progress:</b> <b>2</b> / <b>10</b>") {
		t.Errorf("missing progress in Telegram message: %s", text)
	}
	if !strings.Contains(text, "🚨 <b>Findings:</b> <b>3 findings detected</b> 🚨") {
		t.Errorf("missing findings summary in Telegram message: %s", text)
	}
}
