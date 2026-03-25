// Package cli – Setup command
//
// This file is intentionally thin. It only contains the cobra command
// definition and a single call into pkg/setup.Run().
// All installation logic lives in the setup package.
package cli

import (
	"github.com/spf13/cobra"

	s "github.com/vishnu303/chaathan-flow/pkg/setup"
)

// ─────────────────────────────────────────────────────────────
// Cobra command
// ─────────────────────────────────────────────────────────────

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install all dependency tools",
	Long: `Installs the tools required for native execution mode.

Categories:
  - Go tools:     subfinder, httpx, nuclei, katana, naabu, etc.
  - Python tools: sublist3r, subdomainizer, linkfinder, arjun
  - From source:  massdns (high-performance DNS resolver)

Already-installed tools are skipped automatically.
All output is logged to ~/.chaathan/logs/setup_<timestamp>.log for debugging.

Usage:
  chaathan setup              # Install tools (parallel)
  chaathan setup --verbose    # Show live install output`,
	Run: runSetup,
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

// ─────────────────────────────────────────────────────────────
// runSetup — cobra handler
// ─────────────────────────────────────────────────────────────

func runSetup(cmd *cobra.Command, args []string) {
	s.Run(s.RunConfig{
		Verbose: Verbose,
	})
}
