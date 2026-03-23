// GF Pattern Installation
//
// Installs a curated set of gf JSON pattern files (~/.gf/) used by
// Step 18 of the wildcard scan to filter live URLs for Nuclei.
package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"os/exec"

	"github.com/vishnu303/chaathan-flow/pkg/progress"
)

// ─────────────────────────────────────────────────────────────
// installGFPatternsSection
// ─────────────────────────────────────────────────────────────

func installGFPatternsSection() (installed, skipped, failed int) {
	progress.Section("gf Patterns", "installing local pattern pack for URL filtering")

	if _, err := exec.LookPath("gf"); err != nil {
		progress.ItemInfo("gf binary not installed yet — skipping pattern install")
		return 0, 1, 0
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

	patterns := map[string]map[string][]string{
		"ssrf": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](url|uri|path|dest|destination|redirect|redirect_uri|redir|return|return_url|next|data|site|domain|feed|host|port|to|out|view|continue|callback|reference)=)`,
			},
		},
		"redirect": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](redirect|redirect_url|redirect_uri|redir|return|return_to|return_url|next|continue|dest|destination|callback)=)`,
			},
		},
		"lfi": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](file|filename|filepath|path|page|include|template|doc|folder|root|pg)=)`,
			},
		},
		"sqli": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](id|ids|user|user_id|uid|account|number|order|sort|group|search|query|filter|report|category|item|product)=)`,
			},
		},
		"xss": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](q|query|search|s|lang|keyword|term|text|message|comment|redirect|url|next|return)=)`,
			},
		},
		"rce": {
			"flags": {"-iE"},
			"patterns": {
				`([?&](cmd|exec|command|execute|ping|query|code|do|daemon|process|upload|download)=)`,
			},
		},
		"idor": {
			"flags": {"-iE"},
			"patterns": {
				`(/(users|user|accounts|orders|order|projects|project|files|file|documents|document|invoices|invoice|tickets|ticket|profiles|profile|messages|message|payments|payment|api)/[^/?#]+)`,
				`([?&](id|user_id|account_id|order_id|project_id|file_id|doc_id|invoice_id|ticket_id|profile_id|message_id|payment_id|uid)=)`,
			},
		},
		"debug_logic": {
			"flags": {"-iE"},
			"patterns": {
				`(/(debug|test|staging|dev|console|actuator|swagger|openapi|internal|admin|config|health|metrics))`,
			},
		},
	}

	installedCount := 0
	skippedCount := 0
	failedCount := 0
	for name, pattern := range patterns {
		path := filepath.Join(gfDir, name+".json")
		if _, err := os.Stat(path); err == nil {
			skippedCount++
			continue
		}

		data, err := json.MarshalIndent(pattern, "", "  ")
		if err != nil {
			progress.ItemFail(name, "failed to marshal pattern")
			failedCount++
			continue
		}
		if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
			progress.ItemFail(name, err.Error())
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
