// Python Tools Installation
//
// Installs pip-based Python security tools (sublist3r, arjun, cloud_enum).
// Creates shell shims in ~/.local/bin/ for pip packages that don't ship a
// stand-alone binary.
package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/vishnu303/chaathan-flow/pkg/progress"
)

// ─────────────────────────────────────────────────────────────
// Tool definitions
// ─────────────────────────────────────────────────────────────

var pyTools = []struct {
	name     string
	package_ string
	cmdName  string
	module   string
}{
	{"cloud_enum", "git+https://github.com/initstring/cloud_enum.git", "cloud_enum.py", "cloud_enum"},
	{"sublist3r", "sublist3r", "sublist3r", "sublist3r"},
	{"arjun", "arjun", "arjun", "arjun"},
}


// ─────────────────────────────────────────────────────────────
// installPythonToolsSection
// ─────────────────────────────────────────────────────────────

func installPythonToolsSection() (installed, skipped, failed int) {
	pip := resolvePip()
	if pip == "" {
		progress.Section("Python Tools", "")
		progress.ItemInfo("pip not found — skipping")
		return 0, 0, 0
	}

	type pyTool struct{ name, pkg, cmd, module string }
	var toInstall []pyTool
	skippedCount := 0
	for _, t := range pyTools {
		if !isForceUpdate() && pythonToolInstalled(t.name, t.cmdName, t.module) {
			_ = ensurePythonToolShim(t.name, t.module)
			skippedCount++
			continue
		}
		toInstall = append(toInstall, pyTool{t.name, t.package_, t.cmdName, t.module})
	}


	totalToInstall := len(toInstall)
	detail := fmt.Sprintf("%d to install, %d already installed", totalToInstall, skippedCount)
	if skippedCount == 0 {
		detail = fmt.Sprintf("%d to install", totalToInstall)
	}
	progress.Section("Python Tools", detail)

	if totalToInstall == 0 {
		progress.ItemInfo("Nothing to do")
		return 0, skippedCount, 0
	}

	tracker := progress.NewTracker(totalToInstall)
	tracker.RunSpinner()

	var wg sync.WaitGroup

	// pip-based tools
	for _, t := range toInstall {
		wg.Add(1)
		go func(tool pyTool) {
			defer wg.Done()
			tracker.Start(tool.name)
			args := []string{"install", "--break-system-packages", tool.pkg}
			cmd := exec.Command(pip, args...)
			if err := captureCommandOutput(cmd, tool.name); err != nil {
				tracker.Fail(tool.name, err.Error())
				return
			}
			// sublist3r and arjun depend on requests/urllib3, but urllib3 v2.x dropped
			// urllib3.packages.six.moves, which both tools rely on. A constraint in the
			// install command above is insufficient when urllib3 v2 is already globally
			// installed — pip won't downgrade an already-satisfied dependency. Force a
			// separate reinstall to guarantee the working 1.26.x series is on disk.
			if tool.name == "sublist3r" || tool.name == "arjun" {
				pinArgs := []string{"install", "--break-system-packages", "--force-reinstall", "urllib3>=1.26.18,<2"}
				pinCmd := exec.Command(pip, pinArgs...)
				if err := captureCommandOutput(pinCmd, tool.name+" (urllib3 pin)"); err != nil {
					tracker.Fail(tool.name, "urllib3 pin failed: "+err.Error())
					return
				}
			}
			if err := ensurePythonToolShim(tool.name, tool.module); err != nil {
				tracker.Fail(tool.name, err.Error())
			} else {
				tracker.Complete(tool.name)
			}
		}(t)
	}


	wg.Wait()
	tracker.StopSpinner()

	i, _, f := tracker.Stats()
	return i, skippedCount, f
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

// resolvePip returns the first available pip binary name, or "" if none found.
func resolvePip() string {
	for _, name := range []string{"pip3", "pip"} {
		if _, err := exec.LookPath(name); err == nil {
			return name
		}
	}
	return ""
}

func pythonToolInstalled(name, cmdName, module string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	if cmdName != "" {
		if _, err := exec.LookPath(cmdName); err == nil {
			return true
		}
	}
	if module != "" && pythonModuleInstalled(module) {
		return true
	}
	return false
}

func pythonModuleInstalled(module string) bool {
	if module == "" {
		return false
	}
	return exec.Command("python3", "-c", "import "+module).Run() == nil
}

func ensurePythonToolShim(name, module string) error {
	if name == "" || module == "" {
		return nil
	}
	if _, err := exec.LookPath(name); err == nil {
		return nil
	}
	if !pythonModuleInstalled(module) {
		return fmt.Errorf("%s module is not importable after install", module)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return err
	}

	shimPath := filepath.Join(binDir, name)
	shim := fmt.Sprintf("#!/usr/bin/env bash\npython3 -m %s \"$@\"\n", module)
	return os.WriteFile(shimPath, []byte(shim), 0755)
}
