// Proxy Tools Installation
//
// Installs proxy automation tools:
// - mubeng: Go-based proxy IP rotator (installed via go install)
// - proxy-scraper-checker: Rust binary (downloaded from nightly CI builds via nightly.link)
//
// mubeng is handled by the Go tools section (it has an InstallURL in the registry).
// proxy-scraper-checker has no stable GitHub Releases — binaries are published as
// nightly CI artifacts (.zip archives) at nightly.link.
package setup

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// ─────────────────────────────────────────────────────────────
// installProxyToolsSection
// ─────────────────────────────────────────────────────────────

func installProxyToolsSection() (installed, skipped, failed int) {
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

// installProxyScraperChecker downloads the proxy-scraper-checker binary from
// nightly.link CI artifacts. The project has no stable GitHub Releases; binaries
// are distributed as .zip archives from the nightly CI workflow.
func installProxyScraperChecker() error {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	// Map Go OS/ARCH → Rust target triple used in artifact names.
	var triple string
	switch {
	case goos == "linux" && goarch == "amd64":
		triple = "x86_64-unknown-linux-gnu"
	case goos == "linux" && goarch == "arm64":
		triple = "aarch64-unknown-linux-gnu"
	case goos == "darwin" && goarch == "amd64":
		triple = "x86_64-apple-darwin"
	case goos == "darwin" && goarch == "arm64":
		triple = "aarch64-apple-darwin"
	case goos == "windows" && goarch == "amd64":
		triple = "x86_64-pc-windows-msvc"
	case goos == "windows" && goarch == "arm64":
		triple = "aarch64-pc-windows-msvc"
	default:
		return fmt.Errorf(
			"unsupported platform %s/%s — download manually from "+
				"https://nightly.link/monosans/proxy-scraper-checker/workflows/ci/main",
			goos, goarch,
		)
	}

	// Artifact URL: each .zip contains one binary named proxy-scraper-checker[.exe]
	downloadURL := fmt.Sprintf(
		"https://nightly.link/monosans/proxy-scraper-checker/workflows/ci/main/proxy-scraper-checker-binary-%s.zip",
		triple,
	)
	writeSetupLog("Downloading proxy-scraper-checker from %s", downloadURL)

	resp, err := http.Get(downloadURL) //nolint:gosec
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d from %s", resp.StatusCode, downloadURL)
	}

	// Read the entire ZIP into memory (~5–10 MB).
	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("download read failed: %w", err)
	}

	// Extract the binary from the archive.
	binName := "proxy-scraper-checker"
	if goos == "windows" {
		binName += ".exe"
	}
	binBytes, err := extractFromZip(zipData, binName)
	if err != nil {
		return fmt.Errorf("zip extraction failed: %w", err)
	}

	// Install to ~/.local/bin/
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("cannot create bin dir %s: %w", binDir, err)
	}

	binPath := filepath.Join(binDir, binName)
	if err := os.WriteFile(binPath, binBytes, 0755); err != nil {
		return fmt.Errorf("cannot write binary: %w", err)
	}
	writeSetupLog("Installed proxy-scraper-checker to %s (%d bytes)", binPath, len(binBytes))

	// Verify the file is non-empty — proxy-scraper-checker is a TUI binary
	// with no --version/--help flags, so exec-based smoke-testing always fails.
	info, err := os.Stat(binPath)
	if err != nil || info.Size() == 0 {
		return fmt.Errorf("binary verification failed: file missing or empty at %s", binPath)
	}
	writeSetupLog("Verified proxy-scraper-checker: %s (%d bytes)", binPath, info.Size())
	return nil
}

// extractFromZip finds a file by name inside a ZIP archive (provided as raw bytes)
// and returns its contents. Matches both bare filenames and path-prefixed entries.
func extractFromZip(zipData []byte, name string) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("cannot open zip: %w", err)
	}
	for _, f := range r.File {
		base := filepath.Base(f.Name)
		if base == name {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("cannot open %s in zip: %w", name, err)
			}
			defer rc.Close()
			data, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("cannot read %s from zip: %w", name, err)
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("binary %q not found in zip archive", name)
}
