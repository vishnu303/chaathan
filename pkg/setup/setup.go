// Package setup orchestrates installation of all chaathan dependency tools.
package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/vishnu303/chaathan/pkg/progress"
)

// RunConfig holds the configuration options passed from the CLI layer.
type RunConfig struct {
	Verbose     bool
	ForceUpdate bool // reinstall all tools even if already present
}

// SetupContext holds the configurations and resources for the current setup execution.
type SetupContext struct {
	Config RunConfig
	Logger *SetupLogger
}

// IsVerbose returns true when verbose logging is enabled.
func (c *SetupContext) IsVerbose() bool {
	return c.Config.Verbose
}

// IsForceUpdate returns true when tools should be reinstalled even if present.
func (c *SetupContext) IsForceUpdate() bool {
	return c.Config.ForceUpdate
}

// RunCommand executes a command without any timeout, streaming/logging via SetupLogger.
func (c *SetupContext) RunCommand(displayName string, name string, args ...string) error {
	return c.RunCommandInDir("", displayName, name, args...)
}

// RunCommandInDir executes a command in a specified directory without timeout, streaming/logging via SetupLogger.
func (c *SetupContext) RunCommandInDir(dir string, displayName string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if c.Logger != nil {
		return c.Logger.CaptureCommandOutput(cmd, displayName, c.IsVerbose())
	}
	return cmd.Run()
}

// Run executes the complete chaathan setup workflow.
func Run(cfg RunConfig) {
	start := time.Now()

	title := "🔧 Chaathan Setup"
	if cfg.ForceUpdate {
		title = "🔄 Chaathan Setup (update mode — reinstalling all tools)"
	}
	progress.Header(title)

	logger, err := NewSetupLogger()
	if err == nil {
		defer logger.Close()
		progress.ItemInfo(fmt.Sprintf("📝 Log file: %s", logger.Path()))
	}

	ctx := &SetupContext{
		Config: cfg,
		Logger: logger,
	}

	installPrerequisites(ctx)

	if ok, _ := CheckGoInstalledAndAtLeast126(); !ok {
		progress.ItemFail("Go runtime validation failed", "Please install Go 1.26+ manually")
		return
	}

	var totalInstalled, totalSkipped, totalFailed int32

	i, s, f := installGoToolsSection(ctx)
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	i, s, f = installGFPatternsSection(ctx)
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	i, s, f = installPythonToolsSection(ctx)
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	i, s, f = installMassDNSSection(ctx)
	totalInstalled += int32(i)
	totalSkipped += int32(s)
	totalFailed += int32(f)

	if ctx.Logger != nil {
		ctx.Logger.Write("=== Setup Complete ===")
		ctx.Logger.Write("Duration: %s", time.Since(start).Round(time.Second))
		ctx.Logger.Write("Installed: %d, Skipped: %d, Failed: %d", totalInstalled, totalSkipped, totalFailed)
	}

	progress.Summary(totalInstalled, totalSkipped, totalFailed, time.Since(start))
	progress.Tip("Ensure $GOPATH/bin is in your $PATH")

	if totalFailed > 0 && logger != nil {
		progress.Tip(fmt.Sprintf("Check log for errors: %s", logger.Path()))
	}
}

// resolveGOPATH returns the resolved GOPATH directory path, defaulting to ~/go.
func resolveGOPATH() string {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			gopath = filepath.Join(home, "go")
		}
	}
	return gopath
}
