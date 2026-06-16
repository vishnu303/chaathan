package cli_test

import (
	"os"
	"testing"

	"github.com/vishnu303/chaathan/cli"
)

func TestCLIHelpAndVersion(t *testing.T) {
	tempDir := t.TempDir()
	os.Setenv("CHAATHAN_HOME", tempDir)
	defer os.Unsetenv("CHAATHAN_HOME")

	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// 1. Test running with --help
	os.Args = []string{"chaathan", "--help"}
	err := cli.Execute()
	if err != nil {
		t.Fatalf("unexpected error running help command: %v", err)
	}

	// 2. Test running version command
	os.Args = []string{"chaathan", "version"}
	err = cli.Execute()
	if err != nil {
		t.Fatalf("unexpected error running version command: %v", err)
	}
}
