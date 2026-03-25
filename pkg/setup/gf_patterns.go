// GF Pattern Installation
//
// Installs the upstream coffinxp/GFpattren JSON files (~/.gf/) used by
// the wildcard workflow for JS/secret scanning and URL filtering.
package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vishnu303/chaathan-flow/pkg/progress"
)

// ─────────────────────────────────────────────────────────────
// installGFPatternsSection
// ─────────────────────────────────────────────────────────────

func installGFPatternsSection() (installed, skipped, failed int) {
	progress.Section("gf Patterns", "cloning upstream GFpattren pack for workflow scanning")

	if _, err := exec.LookPath("gf"); err != nil {
		progress.ItemInfo("gf binary not installed yet — skipping pattern install")
		return 0, 1, 0
	}
	if _, err := exec.LookPath("git"); err != nil {
		progress.ItemFail("git", "git is required to install gf patterns")
		return 0, 0, 1
	}

	home, err := os.UserHomeDir()
	if err != nil {
		progress.ItemFail("gf patterns", "cannot determine home directory")
		return 0, 0, 1
	}

	gfDir := filepath.Join(home, ".gf")
	if err := os.MkdirAll(gfDir, 0755); err != nil {
		progress.ItemFail("gf patterns", err.Error())
		return 0, 0, 1
	}

	tempDir, err := os.MkdirTemp("", "chaathan-gf-*")
	if err != nil {
		progress.ItemFail("gf patterns", "failed to create temp directory")
		return 0, 0, 1
	}
	defer os.RemoveAll(tempDir)

	cloneCmd := exec.Command("git", "clone", "--depth", "1", "https://github.com/coffinxp/GFpattren", tempDir)
	output, err := cloneCmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			detail = err.Error()
		}
		progress.ItemFail("gf patterns", detail)
		return 0, 0, 1
	}

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		progress.ItemFail("gf patterns", "failed to read cloned pattern pack")
		return 0, 0, 1
	}

	installedCount := 0
	skippedCount := 0
	failedCount := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		srcPath := filepath.Join(tempDir, entry.Name())
		dstPath := filepath.Join(gfDir, entry.Name())
		if _, err := os.Stat(dstPath); err == nil {
			skippedCount++
			continue
		}

		data, err := os.ReadFile(srcPath)
		if err != nil {
			progress.ItemFail(entry.Name(), err.Error())
			failedCount++
			continue
		}
		if err := os.WriteFile(dstPath, data, 0644); err != nil {
			progress.ItemFail(entry.Name(), err.Error())
			failedCount++
			continue
		}
		installedCount++
	}

	if installedCount > 0 {
		progress.ItemOK(fmt.Sprintf("%d gf patterns installed", installedCount))
	}
	if installedCount == 0 && failedCount == 0 {
		progress.ItemInfo("gf pattern pack already present")
	}

	return installedCount, skippedCount, failedCount
}
