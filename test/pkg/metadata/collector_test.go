package metadata_test
 
import (
	"testing"

	"github.com/vishnu303/chaathan/pkg/metadata"
)

func TestAnalyzeCookies_NoCookies(t *testing.T) {
	insecure, session := metadata.AnalyzeCookies(nil)
	if insecure || session {
		t.Fatal("empty cookies should return false/false")
	}
}

func TestAnalyzeCookies_SecureHTTPOnly(t *testing.T) {
	cookies := []string{
		"JSESSIONID=abc123; Path=/; Secure; HttpOnly",
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	if insecure {
		t.Fatal("cookie with Secure+HttpOnly should NOT be flagged insecure")
	}
	if !session {
		t.Fatal("JSESSIONID should be detected as a session cookie")
	}
}

func TestAnalyzeCookies_MissingSecure(t *testing.T) {
	cookies := []string{
		"session_id=xyz789; Path=/; HttpOnly",
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	if !insecure {
		t.Fatal("cookie missing Secure flag should be flagged insecure")
	}
	if !session {
		t.Fatal("session_id should be detected as a session cookie")
	}
}

func TestAnalyzeCookies_MissingHTTPOnly(t *testing.T) {
	cookies := []string{
		"auth_token=abc; Path=/; Secure",
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	if !insecure {
		t.Fatal("cookie missing HttpOnly flag should be flagged insecure")
	}
	if !session {
		t.Fatal("auth_token should be detected as a session cookie")
	}
}

func TestAnalyzeCookies_NonSessionCookie(t *testing.T) {
	cookies := []string{
		"theme=dark; Path=/",
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	if !insecure {
		t.Fatal("cookie with no security flags should be flagged insecure")
	}
	if session {
		t.Fatal("theme cookie should NOT be detected as a session cookie")
	}
}

func TestAnalyzeCookies_MultipleCookies(t *testing.T) {
	cookies := []string{
		"_ga=GA1.2.123; Path=/",                          // tracking, insecure
		"PHPSESSID=abc123; Path=/; Secure; HttpOnly",      // session, secure
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	if !insecure {
		t.Fatal("at least one cookie lacks security flags — should be insecure")
	}
	if !session {
		t.Fatal("PHPSESSID should be detected as a session cookie")
	}
}

func TestAnalyzeCookies_CaseInsensitive(t *testing.T) {
	cookies := []string{
		"Connect.Sid=abc; Path=/; SECURE; HTTPONLY",
	}
	insecure, session := metadata.AnalyzeCookies(cookies)
	// Attributes are checked case-insensitively
	if insecure {
		t.Fatal("cookie with both flags (case-insensitive) should not be insecure")
	}
	if !session {
		t.Fatal("connect.sid should be detected as a session cookie")
	}
}

func TestDedupeByHost(t *testing.T) {
	urls := []string{
		"https://example.com/path1",
		"https://example.com/path2",
		"https://sub.example.com/path1",
		"https://EXAMPLE.COM/path3",
	}
	result := metadata.DedupeByHost(urls)
	if len(result) != 2 {
		t.Fatalf("expected 2 unique hosts, got %d: %v", len(result), result)
	}
}

func TestDedupeByURL(t *testing.T) {
	urls := []string{
		"https://example.com/path1",
		"https://example.com/path1",
		"https://example.com/path2",
		"",
		"  ",
	}
	result := metadata.DedupeByURL(urls)
	if len(result) != 2 {
		t.Fatalf("expected 2 unique URLs, got %d: %v", len(result), result)
	}
}
