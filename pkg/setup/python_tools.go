// Python Tools Installation
//
// Installs pip-based Python security tools (sublist3r, linkfinder, arjun,
// cloud_enum) and script-based tools cloned directly from GitHub (subdomainizer).
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
	{"sublist3r", "git+https://github.com/aboul3la/Sublist3r.git", "sublist3r.py", "sublist3r"},
	{"linkfinder", "git+https://github.com/GerbenJavado/LinkFinder.git", "linkfinder.py", "linkfinder"},
	{"arjun", "arjun", "arjun", "arjun"},
}

// Python scripts that need manual cloning (not available via pip)
var pyScripts = []struct {
	name   string
	repo   string
	script string
}{
	{"subdomainizer", "https://github.com/nsonaniya2010/SubDomainizer.git", "SubDomainizer.py"},
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
		if !forceUpdate && pythonToolInstalled(t.name, t.cmdName, t.module) {
			_ = ensurePythonToolShim(t.name, t.module)
			skippedCount++
			continue
		}
		toInstall = append(toInstall, pyTool{t.name, t.package_, t.cmdName, t.module})
	}

	type pyScript struct{ name, repo, script string }
	var scriptsToInstall []pyScript
	for _, t := range pyScripts {
		if !forceUpdate {
			if _, err := exec.LookPath(t.name); err == nil {
				skippedCount++
				continue
			}
		}
		scriptsToInstall = append(scriptsToInstall, pyScript{t.name, t.repo, t.script})
	}

	totalToInstall := len(toInstall) + len(scriptsToInstall)
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
			cmd := exec.Command(pip, "install", "--break-system-packages", tool.pkg)
			if err := captureCommandOutput(cmd, tool.name); err != nil {
				tracker.Fail(tool.name, err.Error())
			} else if err := ensurePythonToolShim(tool.name, tool.module); err != nil {
				tracker.Fail(tool.name, err.Error())
			} else {
				tracker.Complete(tool.name)
			}
		}(t)
	}

	// script-based tools (clone + copy binary)
	for _, t := range scriptsToInstall {
		wg.Add(1)
		go func(tool pyScript) {
			defer wg.Done()
			tracker.Start(tool.name)

			goPath := os.Getenv("GOPATH")
			if goPath == "" {
				home, _ := os.UserHomeDir()
				goPath = filepath.Join(home, "go")
			}
			binDir := filepath.Join(goPath, "bin")

			tempDir, err := os.MkdirTemp("", tool.name+"_*")
			if err != nil {
				tracker.Fail(tool.name, err.Error())
				return
			}
			defer os.RemoveAll(tempDir)

			cloneCmd := exec.Command("git", "clone", "--depth", "1", tool.repo, tempDir)
			if err := captureCommandOutput(cloneCmd, tool.name+" (clone)"); err != nil {
				tracker.Fail(tool.name, "clone failed")
				return
			}

			// Install requirements if they exist (e.g. termcolor for SubDomainizer).
			// A missing dependency will cause the tool to fail at runtime, so treat
			// a requirements install failure as a hard failure here.
			reqFile := filepath.Join(tempDir, "requirements.txt")
			if _, err := os.Stat(reqFile); err == nil {
				reqCmd := exec.Command(pip, "install", "--break-system-packages", "-r", reqFile)
				if err := captureCommandOutput(reqCmd, tool.name+" (reqs)"); err != nil {
					tracker.Fail(tool.name, "requirements install failed: "+err.Error())
					return
				}
			}

			src := filepath.Join(tempDir, tool.script)
			dst := filepath.Join(binDir, tool.name)
			input, err := os.ReadFile(src)
			if err != nil {
				tracker.Fail(tool.name, "read failed")
				return
			}
			if err := os.WriteFile(dst, input, 0755); err != nil {
				tracker.Fail(tool.name, "write failed")
				return
			}
			tracker.Complete(tool.name)
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
