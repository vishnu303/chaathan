package setup

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// CheckGoInstalledAndAtLeast126 checks if go is in PATH and if its version is >= 1.26.
func CheckGoInstalledAndAtLeast126() (bool, string) {
	if runtime.GOOS == "linux" {
		currentPath := os.Getenv("PATH")
		goBin := "/usr/local/go/bin"
		if !strings.Contains(currentPath, goBin) {
			if _, err := os.Stat("/usr/local/go/bin/go"); err == nil {
				currentPath = currentPath + string(os.PathListSeparator) + goBin
				_ = os.Setenv("PATH", currentPath)
			}
		}
	}

	path, err := exec.LookPath("go")
	if err != nil {
		return false, ""
	}
	cmd := exec.Command(path, "version")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return false, path
	}
	versionStr := out.String()
	
	// Clean string e.g. "go version go1.26.1 linux/amd64"
	fields := strings.Fields(versionStr)
	for _, f := range fields {
		if strings.HasPrefix(f, "go") && f != "go" {
			v := strings.TrimPrefix(f, "go")
			// Remove non-numeric suffixes like rc1, beta2
			if idx := strings.IndexAny(v, "abcdefghijklmnopqrstuvwxyz"); idx >= 0 {
				v = v[:idx]
			}
			parts := strings.Split(v, ".")
			if len(parts) >= 2 {
				major, _ := strconv.Atoi(parts[0])
				minor, _ := strconv.Atoi(parts[1])
				if major > 1 || (major == 1 && minor >= 26) {
					return true, f
				}
			}
			return false, f
		}
	}
	return false, ""
}

// downloadLatestGo fetches the latest Go version string from go.dev, falling back to go1.26.0 on failure.
func downloadLatestGo(ctx *SetupContext) (string, error) {
	progress.ItemPending("Checking latest Go version on go.dev...")
	resp, err := http.Get("https://go.dev/VERSION?m=text")
	if err != nil {
		progress.ItemInfo("Failed to check go.dev/VERSION (using go1.26.0 as fallback)")
		return "go1.26.0", nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		progress.ItemInfo("Failed to read go.dev/VERSION (using go1.26.0 as fallback)")
		return "go1.26.0", nil
	}
	version := strings.TrimSpace(string(body))
	if idx := strings.Index(version, "\n"); idx >= 0 {
		version = strings.TrimSpace(version[:idx])
	}
	if !strings.HasPrefix(version, "go") {
		progress.ItemInfo("Invalid go.dev/VERSION output (using go1.26.0 as fallback)")
		return "go1.26.0", nil
	}
	progress.ItemOK(fmt.Sprintf("Latest Go version: %s", version))
	return version, nil
}

// downloadTarball downloads Go binary from go.dev to the destination path.
func downloadTarball(ctx *SetupContext, version, destPath string) error {
	url := fmt.Sprintf("https://go.dev/dl/%s.linux-amd64.tar.gz", version)
	progress.ItemPending(fmt.Sprintf("Downloading Go archive: %s", url))
	
	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code from go.dev: %s", resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	return err
}

// installGoBinary executes tarball extraction to /usr/local.
func installGoBinary(ctx *SetupContext, tarPath string) error {
	progress.ItemPending("Purging old Go installation and extracting tarball...")
	
	// Delete any old custom installations to avoid conflicts
	if err := runSysCmd(ctx, "sudo", "rm", "-rf", "/usr/local/go"); err != nil {
		return fmt.Errorf("purge /usr/local/go failed: %w", err)
	}

	// Extract new package to /usr/local
	if err := runSysCmd(ctx, "sudo", "tar", "-C", "/usr/local", "-xzf", tarPath); err != nil {
		return fmt.Errorf("tar extract to /usr/local failed: %w", err)
	}

	return nil
}

// ensureGoPATH adds /usr/local/go/bin to the configuration files of common shells.
func ensureGoPATH() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	comment := "# Go installation PATH"
	pathsToAdd := []string{
		`export PATH=$PATH:/usr/local/go/bin`,
	}

	rcFiles := []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
	}

	for _, rc := range rcFiles {
		if _, err := os.Stat(rc); os.IsNotExist(err) {
			continue
		}
		_, _ = appendLinesToFile(rc, pathsToAdd, comment)
	}

	// Fish shell support
	fishConfig := filepath.Join(home, ".config", "fish", "config.fish")
	if _, err := os.Stat(fishConfig); err == nil {
		fishPaths := []string{
			`fish_add_path -g /usr/local/go/bin`,
		}
		_, _ = appendLinesToFile(fishConfig, fishPaths, comment)
	}

	// Update PATH of the current running process so LookPath resolves immediately
	currentPath := os.Getenv("PATH")
	goBin := "/usr/local/go/bin"
	if !strings.Contains(currentPath, goBin) {
		currentPath = currentPath + string(os.PathListSeparator) + goBin
		_ = os.Setenv("PATH", currentPath)
	}
}

// EnsureGoInstalled checks if Go runtime is ready and runs the installer if missing or old.
func EnsureGoInstalled(ctx *SetupContext) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("automated Go installation is only supported on Linux")
	}

	ok, currentVer := CheckGoInstalledAndAtLeast126()
	if ok {
		progress.ItemOK(fmt.Sprintf("Go is ready (version: %s)", currentVer))
		return true, nil
	}

	if currentVer != "" {
		progress.ItemInfo(fmt.Sprintf("Go version %s is too old (minimum required: Go 1.26)", currentVer))
	} else {
		progress.ItemInfo("Go is not installed on the system")
	}

	progress.ItemPending("Preparing Go installer...")
	
	version, err := downloadLatestGo(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to detect latest Go version: %w", err)
	}

	tarPath := "/tmp/go.tar.gz"
	defer os.Remove(tarPath)

	if err := downloadTarball(ctx, version, tarPath); err != nil {
		return false, fmt.Errorf("download Go tarball failed: %w", err)
	}

	if err := installGoBinary(ctx, tarPath); err != nil {
		return false, fmt.Errorf("install Go binary failed: %w", err)
	}

	ensureGoPATH()

	// Verify new Go path resolutions
	okVerify, newVer := CheckGoInstalledAndAtLeast126()
	if !okVerify {
		return false, fmt.Errorf("go installation completed but verification failed (version check resolved: %s)", newVer)
	}

	progress.ItemOK(fmt.Sprintf("Go version %s successfully installed", newVer))
	return true, nil
}
