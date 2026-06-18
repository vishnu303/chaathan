// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// installX8Section checks and installs x8.
// It first attempts to download the precompiled binary from GitHub Releases.
// If that fails, it falls back to installing via Cargo.
func installX8Section(ctx *SetupContext) (installed, skipped, failed int) {
	progress.Section("x8", "Parameter Discovery Tool")

	if !ctx.IsForceUpdate() {
		if _, err := exec.LookPath("x8"); err == nil {
			progress.ItemOK("Already installed")
			return 0, 1, 0
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		progress.ItemFail("x8", "failed to find user home dir: "+err.Error())
		return 0, 0, 1
	}
	localDir := filepath.Join(home, ".local")
	binDir := filepath.Join(localDir, "bin")
	dst := filepath.Join(binDir, "x8")

	// Ensure bin directory exists
	if err := os.MkdirAll(binDir, 0755); err != nil {
		progress.ItemFail("x8", "failed to create local bin dir: "+err.Error())
		return 0, 0, 1
	}

	// Try downloading precompiled binary first if on Linux AMD64
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		tracker := progress.NewTracker(1)
		tracker.RunSpinner()
		tracker.Start("downloading precompiled x8")

		downloadURL := "https://github.com/Sh1Yo/x8/releases/download/v4.3.0/x86_64-linux-x8.gz"
		err := downloadAndDecompressGzip(downloadURL, dst)
		if err == nil {
			tracker.Complete("downloading precompiled x8")
			tracker.StopSpinner()
			return 1, 0, 0
		}

		tracker.Fail("downloading precompiled x8", err.Error()+"; falling back to Cargo build")
		tracker.StopSpinner()
	}

	// Fallback to Cargo install
	tracker := progress.NewTracker(1)
	tracker.RunSpinner()
	tracker.Start("cargo install x8")

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

// downloadAndDecompressGzip downloads a gzipped file and extracts it to destination.
func downloadAndDecompressGzip(url, dst string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code: %s", resp.Status)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gr.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, gr)
	return err
}
