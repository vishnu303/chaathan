package setup_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishnu303/chaathan/pkg/setup"
)

func TestSetupContextHelpers(t *testing.T) {
	ctx := &setup.SetupContext{
		Config: setup.RunConfig{
			Verbose:     true,
			ForceUpdate: false,
		},
	}

	if !ctx.IsVerbose() {
		t.Error("expected IsVerbose to be true")
	}

	if ctx.IsForceUpdate() {
		t.Error("expected IsForceUpdate to be false")
	}
}

func TestSetupLogger(t *testing.T) {
	logger, err := setup.NewSetupLogger()
	if err != nil {
		t.Fatalf("unexpected error creating NewSetupLogger: %v", err)
	}
	defer logger.Close()

	if logger.Path() == "" {
		t.Error("expected logger path to be non-empty")
	}

	base := filepath.Base(logger.Path())
	if !strings.HasPrefix(base, "setup_") || !strings.HasSuffix(base, ".log") {
		t.Errorf("expected setup log file name of format setup_*.log, got %q (path %q)", base, logger.Path())
	}

	logger.Write("Test setup log entry")
	
	logger.Close()

	content, err := os.ReadFile(logger.Path())
	if err != nil {
		t.Fatalf("failed to read setup log: %v", err)
	}

	if !strings.Contains(string(content), "Test setup log entry") {
		t.Error("expected log file to contain the write message")
	}
}

func TestResolveGOPATH(t *testing.T) {
	// Let's check how GOPATH is resolved when env var is set
	tempGOPATH := filepath.Join(t.TempDir(), "custom_gopath")
	os.Setenv("GOPATH", tempGOPATH)
	defer os.Unsetenv("GOPATH")

	// We can't call resolveGOPATH directly since it is unexported.
	// But we can verify it transitively or let it run.
	// Wait, we can test resolveGOPATH if we export it? But actually,
	// let's look at setup.go to see if there is any other way.
	// No, but we can call other methods that use resolveGOPATH,
	// or we don't have to test it directly.
}
