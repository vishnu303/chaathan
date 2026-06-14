// Go Tools Installation
//
// Installs Go-based security tools sequentially via `go install`.
// The tool list is derived from pkg/tools/registry.go — the single
// source of truth — filtered to only Go-installable entries.
package setup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/vishnu303/chaathan/pkg/progress"
	"github.com/vishnu303/chaathan/pkg/tools"
)

// ─────────────────────────────────────────────────────────────
// installGoToolsSection
// ─────────────────────────────────────────────────────────────

func installGoToolsSection() (installed, skipped, failed int) {
	// Separate already-installed tools from those that need installing
	type goTool struct{ name, url string }
	var toInstall []goTool
	skippedCount := 0
	for _, t := range tools.GoInstallableTools() {
		if !isForceUpdate() {
			if _, err := exec.LookPath(t.Name); err == nil {
				skippedCount++
				continue
			}
		}
		toInstall = append(toInstall, goTool{t.Name, t.InstallURL})
	}

	detail := fmt.Sprintf("%d to install, %d already installed", len(toInstall), skippedCount)
	if skippedCount == 0 {
		detail = fmt.Sprintf("%d to install", len(toInstall))
	}
	progress.Section("Go Tools", detail)

	if len(toInstall) == 0 {
		progress.ItemInfo("Nothing to do")
		return 0, skippedCount, 0
	}

	tracker := progress.NewTracker(len(toInstall))
	tracker.RunSpinner()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 1) // sequential: prevents OOM during heavy compilation

	for _, t := range toInstall {
		wg.Add(1)
		go func(tool goTool) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tracker.Start(tool.name)
			if err := installGoTool(tool.name, tool.url); err != nil {
				tracker.Fail(tool.name, err.Error())
			} else {
				tracker.Complete(tool.name)
				if tool.name == "nuclei" {
					_ = downloadNucleiTemplates() // best effort
				}
			}
		}(t)
	}

	wg.Wait()
	tracker.StopSpinner()

	i, _, f := tracker.Stats()
	return i, skippedCount, f
}

// ─────────────────────────────────────────────────────────────
// installGoTool — go install with 10-minute timeout
// ─────────────────────────────────────────────────────────────

func installGoTool(name, url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "install", "-v", url)
	return captureCommandOutput(cmd, name)
}

// downloadNucleiTemplates runs nuclei -update-templates to populate the templates directory.
func downloadNucleiTemplates() error {
	// Find nuclei binary path
	nucleiPath, err := exec.LookPath("nuclei")
	if err != nil {
		// Try to find it in the standard GOPATH/bin as a fallback
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			if home, err := os.UserHomeDir(); err == nil {
				gopath = filepath.Join(home, "go")
			}
		}
		if gopath != "" {
			candidate := filepath.Join(gopath, "bin", "nuclei")
			if _, err := os.Stat(candidate); err == nil {
				nucleiPath = candidate
			}
		}
	}

	if nucleiPath == "" {
		return fmt.Errorf("nuclei binary not found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, nucleiPath, "-update-templates")
	return cmd.Run()
}
