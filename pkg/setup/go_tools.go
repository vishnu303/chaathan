// Go Tools Installation
//
// Defines the list of Go-based security tools and installs them
// sequentially via `go install` (sequential to avoid OOM during heavy compilation).
package setup

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/vishnu303/chaathan-flow/pkg/progress"
)

// ─────────────────────────────────────────────────────────────
// Go tool definitions
// ─────────────────────────────────────────────────────────────

var goTools = []struct {
	name string
	url  string
}{
	{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
	{"amass", "github.com/owasp-amass/amass/v4/...@latest"},
	{"nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
	{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
	{"assetfinder", "github.com/tomnomnom/assetfinder@latest"},
	{"gau", "github.com/lc/gau/v2/cmd/gau@latest"},
	{"metabigor", "github.com/j3ssie/metabigor@latest"},
	{"shuffledns", "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"},
	{"anew", "github.com/tomnomnom/anew@latest"},
	{"gf", "github.com/tomnomnom/gf@latest"},
	{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
	{"katana", "github.com/projectdiscovery/katana/cmd/katana@latest"},
	{"ffuf", "github.com/ffuf/ffuf/v2@latest"},
	{"gospider", "github.com/jaeles-project/gospider@latest"},
	{"waybackurls", "github.com/tomnomnom/waybackurls@latest"},
	{"github-subdomains", "github.com/gwen001/github-subdomains@latest"},
	{"subjack", "github.com/haccer/subjack@latest"},
	{"dalfox", "github.com/hahwul/dalfox/v2@latest"},
	{"tlsx", "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"},
	{"uncover", "github.com/projectdiscovery/uncover/cmd/uncover@latest"},
}

// ─────────────────────────────────────────────────────────────
// installGoToolsSection
// ─────────────────────────────────────────────────────────────

func installGoToolsSection() (installed, skipped, failed int) {
	// Separate already-installed tools from those that need installing
	type goTool struct{ name, url string }
	var toInstall []goTool
	skippedCount := 0
	for _, t := range goTools {
		if !forceUpdate {
			if _, err := exec.LookPath(t.name); err == nil {
				skippedCount++
				continue
			}
		}
		toInstall = append(toInstall, goTool{t.name, t.url})
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
