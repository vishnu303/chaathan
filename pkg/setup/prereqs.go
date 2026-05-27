// Prerequisites Installation
//
// Checks and installs system-level packages (go, pip3, git, gcc, libpcap-dev…)
// required before any tool installation can begin.
package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// ─────────────────────────────────────────────────────────────
// installPrerequisites
// ─────────────────────────────────────────────────────────────

func installPrerequisites() {
	progress.Section("Prerequisites", "")

	if runtime.GOOS != "linux" {
		progress.ItemInfo("Auto-install only supported on Ubuntu/Debian.")
		progress.ItemInfo("Please ensure: go, pip3, gem, git, make, gcc, libpcap-dev")
		return
	}

	type prereq struct {
		name, binary, aptPkg, dpkgPkg string
	}

	prereqs := []prereq{
		{"Go", "go", "golang-go", ""},
		{"pip3", "pip3", "python3-pip", ""},
		{"Ruby gem", "gem", "ruby-full", ""},
		{"Git", "git", "git", ""},
		{"Make", "make", "make", ""},
		{"GCC", "gcc", "gcc", ""},
		{"libpcap-dev", "", "libpcap-dev", "libpcap-dev"},
	}

	var toInstall []string
	for _, p := range prereqs {
		if isInstalled(p.binary, p.dpkgPkg) {
			progress.ItemOK(p.name)
		} else {
			progress.ItemPending(p.name)
			toInstall = append(toInstall, p.aptPkg)
		}
	}

	if len(toInstall) == 0 {
		progress.ItemInfo("All prerequisites ready")
		return
	}

	progress.ItemInfo(fmt.Sprintf("Installing %d packages via apt...", len(toInstall)))
	runSysCmd("sudo", "apt", "update", "-qq")
	if err := runSysCmd("sudo", append([]string{"apt", "install", "-y", "-qq"}, toInstall...)...); err != nil {
		progress.ItemFail("apt install", err.Error())
	} else {
		progress.ItemOK(fmt.Sprintf("%d packages installed", len(toInstall)))
	}

	ensurePathSetup()
}

// ─────────────────────────────────────────────────────────────
// isInstalled — check binary presence or dpkg install status
// ─────────────────────────────────────────────────────────────

func isInstalled(binary, dpkgPkg string) bool {
	if binary != "" {
		_, err := exec.LookPath(binary)
		return err == nil
	}
	if dpkgPkg != "" {
		return exec.Command("dpkg", "-l", dpkgPkg).Run() == nil
	}
	return false
}

// ─────────────────────────────────────────────────────────────
// runSysCmd — run a system command with inherited stdio
// ─────────────────────────────────────────────────────────────

func runSysCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ─────────────────────────────────────────────────────────────
// ensurePathSetup — add ~/.local/bin and ~/go/bin to PATH in rc files
// ─────────────────────────────────────────────────────────────

func ensurePathSetup() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	pathsToAdd := []string{
		`export PATH="$HOME/.local/bin:$PATH"`,
		`export PATH="$HOME/go/bin:$PATH"`,
	}

	rcFiles := []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
	}

	for _, rc := range rcFiles {
		if _, err := os.Stat(rc); os.IsNotExist(err) {
			continue // skip if the user doesn't use this shell
		}

		content, err := os.ReadFile(rc)
		if err != nil {
			continue
		}

		fileContent := string(content)
		added := false

		f, err := os.OpenFile(rc, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			continue
		}

		for _, p := range pathsToAdd {
			if !strings.Contains(fileContent, p) {
				if !added {
					f.WriteString("\n# Chaathan PATH configuration\n")
					added = true
				}
				f.WriteString(p + "\n")
			}
		}
		f.Close()

		if added {
			progress.ItemOK(fmt.Sprintf("Added paths to %s (Restart terminal to apply)", filepath.Base(rc)))
		}
	}

	// Also update the current Go process's PATH so that subsequent setup functions 
	// or tool runs in this same execution session can find the new paths instantly.
	currentPath := os.Getenv("PATH")
	localBin := filepath.Join(home, ".local", "bin")
	goBin := filepath.Join(home, "go", "bin")

	if !strings.Contains(currentPath, localBin) {
		currentPath = localBin + string(os.PathListSeparator) + currentPath
	}
	if !strings.Contains(currentPath, goBin) {
		currentPath = goBin + string(os.PathListSeparator) + currentPath
	}
	os.Setenv("PATH", currentPath)
}
