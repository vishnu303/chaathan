package runner_test

import (
	"context"
	"testing"
	"time"

	"github.com/vishnu303/chaathan/pkg/runner"
)

func TestNativeRunner_Success(t *testing.T) {
	// NativeRunner runs local commands. In WSL, 'whoami' or 'echo' exists.
	run := runner.NewWithRetry("native", false, 0, 0)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	output, err := run.Run(ctx, "whoami", nil)
	if err != nil {
		t.Fatalf("unexpected error running whoami: %v", err)
	}

	if len(output) == 0 {
		t.Error("expected non-empty output from whoami")
	}
}

func TestNativeRunner_RetryAndFailure(t *testing.T) {
	// NativeRunner with retries on a nonexistent command
	run := runner.NewWithRetry("native", false, 1, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := run.Run(ctx, "nonexistent-command-xyz-12345", nil)
	if err == nil {
		t.Fatal("expected error running nonexistent command, got nil")
	}
}

func TestRunnerOptions(t *testing.T) {
	// Test that we can use options
	run := runner.NewWithRetry("native", true, 0, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := run.Run(ctx, "whoami", nil,
		runner.WithDir("/tmp"),
		runner.WithTimeout(2*time.Second),
		runner.WithEnv("TEST_VAR=true"),
	)
	if err != nil {
		t.Fatalf("unexpected error running with options: %v", err)
	}
}
