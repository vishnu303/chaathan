// Package orchestrate provides shared infrastructure setup used by both
// wildcard_flow and company_flow. This package owns Runner, ToolBox,
// and Notifier construction as well as common signal handling — logic
// that was previously copy-pasted between both flow packages (F9, F10).
package orchestrate

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vishnu303/chaathan/pkg/config"
	"github.com/vishnu303/chaathan/pkg/logger"
	"github.com/vishnu303/chaathan/pkg/notify"
	"github.com/vishnu303/chaathan/pkg/runner"
	"github.com/vishnu303/chaathan/pkg/tools"
)

// Infra bundles the shared infrastructure components constructed by
// NewInfra. Both wildcard and company flows assign these fields into
// their own Ctx structs.
type Infra struct {
	Runner   runner.Runner
	ToolBox  *tools.ToolBox
	Notifier *notify.Notifier
}

// NewInfra constructs a Runner, ToolBox, and optional Notifier from the
// supplied config.Config. mode and verbose are typically passed from the
// CLI layer (e.g. "native"/"docker" and --verbose).
//
// This replaces the ~40 lines of duplicated setup previously in both
// wildcard_flow/flow.go and company_flow/flow.go.
func NewInfra(mode string, verbose bool, cfg *config.Config) Infra {
	// ── Runner ───────────────────────────────────────────────
	maxRetries := 1
	retryDelay := 3 * time.Second
	if cfg != nil {
		if cfg.General.MaxRetries > 0 {
			maxRetries = cfg.General.MaxRetries
		}
		if cfg.General.RetryDelaySec > 0 {
			retryDelay = time.Duration(cfg.General.RetryDelaySec) * time.Second
		}
	}
	r := runner.NewWithRetry(mode, verbose, maxRetries, retryDelay)

	// ── ToolBox ──────────────────────────────────────────────
	var toolsCfg *config.ToolsConfig
	if cfg != nil {
		toolsCfg = &cfg.Tools
	}
	tb := tools.New(r, toolsCfg)
	if cfg != nil {
		tb.WithGeneral(&cfg.General)
		tb.WithRateLimits(&cfg.RateLimits)
		tb.WithAPIKeys(&cfg.APIKeys)
	}

	// ── Notifier ─────────────────────────────────────────────
	var n *notify.Notifier
	if cfg != nil && cfg.Notifications.Enabled {
		n = notify.New(&cfg.Notifications)
	}

	return Infra{
		Runner:   r,
		ToolBox:  tb,
		Notifier: n,
	}
}

// HandleSignals starts a goroutine that cancels the context on
// SIGINT / SIGTERM. It returns immediately; the goroutine exits
// when ctx is done or when a signal is received.
//
// This replaces the identical signal-handling goroutine that was
// duplicated in wildcard_flow/flow.go and company_flow/flow.go (F10).
func HandleSignals(ctx context.Context, cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			logger.Warning("Received interrupt signal. Stopping...")
			cancel()
		case <-ctx.Done():
			// context already cancelled (e.g. resume error path)
		}
		signal.Stop(sigChan)
	}()
}
