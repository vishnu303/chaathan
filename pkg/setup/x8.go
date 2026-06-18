// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// installX8Section checks and installs x8 via Cargo.
func installX8Section(ctx *SetupContext) (installed, skipped, failed int) {
	progress.Section("x8", "Parameter Discovery Tool")

	if !ctx.IsForceUpdate() {
		if _, err := exec.LookPath("x8"); err == nil {
			progress.ItemOK("Already installed")
			return 0, 1, 0
		}
	}

	tracker := progress.NewTracker(1)
	tracker.RunSpinner()
	tracker.Start("cargo install x8")

	home, err := os.UserHomeDir()
	if err != nil {
		tracker.Fail("cargo install x8", "failed to find user home dir: "+err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}

	localDir := filepath.Join(home, ".local")
	err = ctx.RunCommand("x8", "cargo", "install", "x8", "--root", localDir)
	if err != nil {
		tracker.Fail("cargo install x8", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}

	tracker.Complete("cargo install x8")
	tracker.StopSpinner()
	return 1, 0, 0
}
