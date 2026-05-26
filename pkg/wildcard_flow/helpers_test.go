package wildcard_flow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan-flow/pkg/config"
)

func TestCollectScopedURLs(t *testing.T) {
	// Setup a clean configuration
	config.Cfg = config.DefaultConfig()

	// Create a temporary input file with target crawled URLs
	tmpDir, err := os.MkdirTemp("", "chaathan-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	inputFile := filepath.Join(tmpDir, "urls.txt")
	outputFile := filepath.Join(tmpDir, "filtered.txt")

	urls := []string{
		"http://example.com/api/v1/users?id=1",                               // in-scope, high score (v1, id parameter)
		"http://example.com/api/v1/users?id=2",                               // in-scope, same path, id parameter -> duplicate of above path
		"http://example.com/admin/login?redirect=http://google.com&user=admin", // in-scope, extremely high score (admin, login, redirect, user parameters)
		"http://example.com/static/style.css?v=1.2",                          // in-scope, has static extension -> ignored
		"http://outscope.com/api/v1/users?id=1",                              // different domain -> still included (no domain-scope filter)
		"http://example.com/about",                                           // in-scope, no parameters -> ignored
	}

	err = os.WriteFile(inputFile, []byte(strings.Join(urls, "\n")), 0644)
	if err != nil {
		t.Fatalf("failed to write temp input file: %v", err)
	}

	ctx := &Ctx{
		RunConfig: RunConfig{
			Domain: "example.com",
			Cfg:    config.Cfg,
		},
	}

	// 1. Test uncapped
	count := collectScopedURLs(ctx, inputFile, outputFile, 0)
	if count != 3 {
		t.Errorf("expected 3 filtered URLs, got %d", count)
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	filteredLines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(filteredLines) != 3 {
		t.Errorf("expected 3 output lines, got %d", len(filteredLines))
	}

	// Verify the admin url is first because of high ROI score
	if !strings.Contains(filteredLines[0], "/admin/login") {
		t.Errorf("expected highest-scoring admin URL first, got: %s", filteredLines[0])
	}

	// 2. Test capped at 1
	countCapped := collectScopedURLs(ctx, inputFile, outputFile, 1)
	if countCapped != 1 {
		t.Errorf("expected 1 filtered URL when capped at 1, got %d", countCapped)
	}

	contentCapped, _ := os.ReadFile(outputFile)
	filteredCapped := strings.Split(strings.TrimSpace(string(contentCapped)), "\n")
	if len(filteredCapped) != 1 {
		t.Errorf("expected 1 output line when capped, got %d", len(filteredCapped))
	}
	if !strings.Contains(filteredCapped[0], "/admin/login") {
		t.Errorf("expected highest-scoring admin URL to remain when capped, got: %s", filteredCapped[0])
	}
}
