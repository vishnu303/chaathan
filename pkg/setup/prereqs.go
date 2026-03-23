// Prerequisites Installation
//
// Checks and installs system-level packages (go, pip3, git, gcc, libpcap-dev…)
// required before any tool installation can begin.
package setup

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/vishnu303/chaathan-flow/pkg/progress"
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
