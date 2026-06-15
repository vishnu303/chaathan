package logger_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vishnu303/chaathan/pkg/logger"
)

func TestLoggerFileLogging(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "scan.log")

	// 1. Init file log
	err := logger.InitFileLog(logPath)
	if err != nil {
		t.Fatalf("InitFileLog failed: %v", err)
	}
	defer logger.CloseFileLog()

	// 2. Write log header
	logger.WriteLogHeader("target.com", 123, logPath)

	// 3. Log commands and debug lines
	logger.LogCommand("ping -c 4 target.com")
	logger.FileDebug("Starting scanning pipeline")
	logger.LogToolFailure("ping", "ping -c 4 target.com", "unknown host target.com", nil)
	logger.LogToolSkipped("ping", "ping -c 4 target.com")

	// Close the log file so we can read it
	logger.CloseFileLog()

	contentBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	content := string(contentBytes)

	// Verify headers and content
	if !strings.Contains(content, "=== Chaathan Wildcard Scan Log ===") {
		t.Errorf("expected log header in file content, got: %s", content)
	}
	if !strings.Contains(content, "target.com") {
		t.Errorf("expected target domain in file content")
	}
	if !strings.Contains(content, "ping -c 4 target.com") {
		t.Errorf("expected logged command in file content")
	}
	if !strings.Contains(content, "Starting scanning pipeline") {
		t.Errorf("expected debug log in file content")
	}
	if !strings.Contains(content, "TOOL ERROR: ping") {
		t.Errorf("expected tool error log in file content")
	}
	if !strings.Contains(content, "TOOL SKIPPED: ping") {
		t.Errorf("expected tool skipped log in file content")
	}
}

func TestLoggerFormatDuration(t *testing.T) {
	d1 := 5 * time.Second
	s1 := logger.FmtDuration(d1)
	if s1 != "5s" {
		t.Errorf("expected 5s, got %q", s1)
	}

	d2 := 2*time.Minute + 3*time.Second
	s2 := logger.FmtDuration(d2)
	if s2 != "2m03s" {
		t.Errorf("expected 2m03s, got %q", s2)
	}

	d3 := 1*time.Hour + 4*time.Minute + 12*time.Second
	s3 := logger.FmtDuration(d3)
	if s3 != "1h04m12s" {
		t.Errorf("expected 1h04m12s, got %q", s3)
	}
}

func TestLoggerStdoutOperations(t *testing.T) {
	// Simple test to ensure these print methods do not crash/panic
	logger.InitScanUI(5)
	logger.ScanHeader("Wildcard", "test.com", 42)
	logger.StepHeader("Passive Recon")
	logger.Info("Finding subdomains...")
	logger.SubStep("Running Subfinder")
	logger.Success("Found 10 subdomains")
	logger.Warning("Some source timed out")
	logger.Error("Command failed completely")
	logger.Debug("Verbose debugging info")
	logger.Section("Query Report")
	logger.Command("chaathan diff 1 2")
	logger.NextSteps([]string{"run scan show 42"})
	logger.ScanSummary("completed", "test.com", 42, 5*time.Second, map[string]string{"subdomains": "10"})
}
