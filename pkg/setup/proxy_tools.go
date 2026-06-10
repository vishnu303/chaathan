// Proxy Tools Installation
//
// Installs proxy automation tools:
// - mubeng: Go-based proxy IP rotator (installed via go install)
// - proxy-scraper-checker: Rust-based proxy scraper/checker (downloaded from GitHub releases)
//
// mubeng is already handled by the Go tools section (it has an InstallURL
// in the registry). This file provides the proxy-scraper-checker binary
// downloader since it's a Rust binary without a go install path.
package setup

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// ─────────────────────────────────────────────────────────────
// installProxyToolsSection
// ─────────────────────────────────────────────────────────────

func installProxyToolsSection() (installed, skipped, failed int) {
	// Check if proxy-scraper-checker is already installed
	if !isForceUpdate() {
		if _, err := exec.LookPath("proxy-scraper-checker"); err == nil {
			progress.Section("Proxy Tools", "1 already installed")
			progress.ItemInfo("proxy-scraper-checker already installed")
			return 0, 1, 0
		}
	}

	progress.Section("Proxy Tools", "1 to install")

	tracker := progress.NewTracker(1)
	tracker.RunSpinner()

	tracker.Start("proxy-scraper-checker")

	if err := installProxyScraperChecker(); err != nil {
		tracker.Fail("proxy-scraper-checker", err.Error())
		tracker.StopSpinner()
		return 0, 0, 1
	}

	tracker.Complete("proxy-scraper-checker")
	tracker.StopSpinner()
	return 1, 0, 0
}

// installProxyScraperChecker downloads the proxy-scraper-checker binary
// from the monosans/proxy-scraper-checker GitHub releases.
func installProxyScraperChecker() error {
	// Determine platform
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	// Map Go OS/ARCH to the release artifact naming convention
	var platform string
	switch {
	case goos == "linux" && goarch == "amd64":
		platform = "x86_64-unknown-linux-gnu"
	case goos == "linux" && goarch == "arm64":
		platform = "aarch64-unknown-linux-gnu"
	case goos == "darwin" && goarch == "amd64":
		platform = "x86_64-apple-darwin"
	case goos == "darwin" && goarch == "arm64":
		platform = "aarch64-apple-darwin"
	case goos == "windows" && goarch == "amd64":
		platform = "x86_64-pc-windows-msvc"
	default:
		return fmt.Errorf("unsupported platform: %s/%s — download manually from https://github.com/monosans/proxy-scraper-checker/releases", goos, goarch)
	}

	// Download from latest release using GitHub API redirect
	// The binary name in releases follows: proxy-scraper-checker-<platform>
	releaseName := "proxy-scraper-checker-" + platform
	if goos == "windows" {
		releaseName += ".exe"
	}

	downloadURL := fmt.Sprintf("https://github.com/monosans/proxy-scraper-checker/releases/latest/download/%s", releaseName)
	writeSetupLog("Downloading proxy-scraper-checker from %s", downloadURL)

	// Download the binary
	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d from %s", resp.StatusCode, downloadURL)
	}

	// Determine install path
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	var binDir string
	var binName string
	if goos == "windows" {
		binDir = filepath.Join(home, ".local", "bin")
		binName = "proxy-scraper-checker.exe"
	} else {
		binDir = filepath.Join(home, ".local", "bin")
		binName = "proxy-scraper-checker"
	}

	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("cannot create bin dir %s: %w", binDir, err)
	}

	binPath := filepath.Join(binDir, binName)

	// Write binary to disk
	f, err := os.OpenFile(binPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("cannot create binary file: %w", err)
	}

	n, err := io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		os.Remove(binPath)
		return fmt.Errorf("download incomplete: %w", err)
	}

	writeSetupLog("Downloaded proxy-scraper-checker: %s (%d bytes)", binPath, n)

	// Verify the binary is executable
	if goos != "windows" {
		if err := os.Chmod(binPath, 0755); err != nil {
			return fmt.Errorf("cannot set executable permission: %w", err)
		}
	}

	// Verify it runs
	cmd := exec.Command(binPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Some versions may not have --version, try --help
		cmd2 := exec.Command(binPath, "--help")
		out2, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("binary verification failed: %v (output: %s)", err, strings.TrimSpace(string(out)))
		}
		_ = out2 // help worked, binary is valid
	}
	writeSetupLog("Verified proxy-scraper-checker: %s", strings.TrimSpace(string(out)))

	return nil
}
