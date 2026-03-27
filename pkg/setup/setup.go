// Package setup orchestrates installation of all chaathan dependency tools.
//
// The CLI shim (cli/setup.go) calls setup.Run() with a RunConfig.
// Each tool category lives in its own file:
//
//   log.go         — log file creation & captureCommandOutput
//   prereqs.go     — system prerequisites (apt packages)
//   go_tools.go    — Go tool list & parallel installer
//   gf_patterns.go — gf JSON pattern pack installer
//   python_tools.go — pip + script-based Python tools
//   massdns.go     — clone → compile → install MassDNS from source
package setup

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/progress"
)

// ─────────────────────────────────────────────────────────────
// RunConfig — supplied by cli/setup.go
// ─────────────────────────────────────────────────────────────

// RunConfig holds the options passed from the CLI layer.
type RunConfig struct {
	Verbose     bool
	ForceUpdate bool // reinstall all tools even if already present
}

// verbose and forceUpdate are set once at the top of Run() and used by
// each section installer.
var verbose bool
var forceUpdate bool

// ─────────────────────────────────────────────────────────────
// Run — main entry point (called by cli/setup.go)
// ─────────────────────────────────────────────────────────────

// Run executes the complete chaathan setup workflow.
func Run(cfg RunConfig) {
	verbose = cfg.Verbose
	forceUpdate = cfg.ForceUpdate
	start := time.Now()

	title := "🔧 Chaathan Setup"
	if forceUpdate {
		title = "🔄 Chaathan Setup (update mode — reinstalling all tools)"
	}
	progress.Header(title)

	initSetupLog()
	if setupLogFile != nil {
		defer setupLogFile.Close()
		progress.ItemInfo(fmt.Sprintf("📝 Log file: %s", setupLogPath))
	}

	installPrerequisites()

	if _, err := exec.LookPath("go"); err != nil {
		progress.ItemFail("Go is not installed", "Please install Go 1.21+ manually")
		return
	}

	var totalInstalled, totalSkipped, totalFailed int32

	i, s, f := installGoToolsSection()
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	i, s, f = installGFPatternsSection()
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	i, s, f = installPythonToolsSection()
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	i, s, f = installMassDNSSection()
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	writeSetupLog("=== Setup Complete ===")
	writeSetupLog("Duration: %s", time.Since(start).Round(time.Second))
	writeSetupLog("Installed: %d, Skipped: %d, Failed: %d", totalInstalled, totalSkipped, totalFailed)

	progress.Summary(totalInstalled, totalSkipped, totalFailed, time.Since(start))
	progress.Tip("Ensure $GOPATH/bin is in your $PATH")

	if totalFailed > 0 {
		progress.Tip(fmt.Sprintf("Check log for errors: %s", setupLogPath))
	}
}
