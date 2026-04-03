// Go Tools Installation
//
// Installs Go-based security tools sequentially via `go install`.
// The tool list is derived from pkg/tools/registry.go — the single
// source of truth — filtered to only Go-installable entries.
package setup

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/progress"
	"github.com/vishnu303/chaathan-flow/pkg/tools"
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
