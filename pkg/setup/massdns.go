// MassDNS Build & Installation
//
// Clones the MassDNS repository, compiles it with `make`, and installs
// the resulting binary into $GOPATH/bin.
// MassDNS is a high-performance DNS stub resolver used by ShuffleDNS.
package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// ─────────────────────────────────────────────────────────────
// installMassDNSSection
// ─────────────────────────────────────────────────────────────

func installMassDNSSection() (installed, skipped, failed int) {
	progress.Section("MassDNS", "")

	if !isForceUpdate() {
		if _, err := exec.LookPath("massdns"); err == nil {
			progress.ItemOK("Already installed")
			return 0, 1, 0
		}
	}

	if runtime.GOOS == "windows" {
		progress.ItemInfo("Windows requires manual install from github.com/blechschmidt/massdns")
		return 0, 0, 0
	}

	tracker := progress.NewTracker(3) // clone, compile, install
	tracker.RunSpinner()

	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			tracker.StopSpinner()
			progress.ItemFail("massdns", "cannot determine home directory")
			return 0, 0, 1
		}
		goPath = filepath.Join(home, "go")
	}
	binDir := filepath.Join(goPath, "bin")

	tempDir, err := os.MkdirTemp("", "massdns_*")
	if err != nil {
		tracker.StopSpinner()
		progress.ItemFail("massdns", "failed to create temp dir")
		return 0, 0, 1
	}
	defer os.RemoveAll(tempDir)

	// Step 1 — Clone
	tracker.Start("clone")
	cloneCmd := exec.Command("git", "clone", "--depth", "1",
		"https://github.com/blechschmidt/massdns.git", tempDir)
	if err := captureCommandOutput(cloneCmd, "massdns (clone)"); err != nil {
		tracker.Fail("clone", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	tracker.Complete("clone")

	// Step 2 — Compile
	tracker.Start("compile")
	makeCmd := exec.Command("make", "-j", fmt.Sprintf("%d", runtime.NumCPU()))
	makeCmd.Dir = tempDir
	if err := captureCommandOutput(makeCmd, "massdns (compile)"); err != nil {
		tracker.Fail("compile", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	tracker.Complete("compile")

	// Step 3 — Install binary
	tracker.Start("install")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		tracker.Fail("install", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	src := filepath.Join(tempDir, "bin", "massdns")
	dst := filepath.Join(binDir, "massdns")
	input, err := os.ReadFile(src)
	if err != nil {
		tracker.Fail("install", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	if err := os.WriteFile(dst, input, 0755); err != nil {
		tracker.Fail("install", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}
	tracker.Complete("install")
	tracker.StopSpinner()

	return 1, 0, 0
}
