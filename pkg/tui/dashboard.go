package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/scan"
)

// Catppuccin color theme constants
const (
	ColorBorder   = "#45475a" // Overlay grey
	ColorActive   = "#cba6f7" // Mauve active highlight
	ColorSubtle   = "#a6adc8" // Subtext muted grey
	ColorLavender = "#b4befe" // Purple
	ColorSapphire = "#74c7ec" // Sky blue
	ColorGreen    = "#a6e3a1" // Green
	ColorRed      = "#f38ba8" // Red
	ColorYellow   = "#f9e2af" // Yellow
	ColorBlue     = "#89b4fa" // Blue
	ColorOrange   = "#fab387" // Orange
)

// StartDashboard boots up the interactive tview dashboard.
func StartDashboard() error {
	app := tview.NewApplication()

	// 1. Header View
	headerText := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	headerText.SetText(fmt.Sprintf(
		" [%s:black:b]CHAATHAN PENTESTING ORCHESTRATOR[-] [%s:black:i]v1.0.0 • Professional Recon Console[-]",
		ColorActive, ColorSapphire,
	))

	// 2. Global Metrics Bar
	topStats := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)

	// Border style helpers
	borderStyle := func(box *tview.Box, title string) {
		box.SetBorder(true).
			SetTitle(" " + title + " ").
			SetTitleColor(tcell.GetColor(ColorSapphire)).
			SetBorderColor(tcell.GetColor(ColorBorder))
	}

	// 3. Left Column: Scan Runs List
	leftList := tview.NewList().
		ShowSecondaryText(true)
	borderStyle(leftList.Box, "SCAN RUNS")
	leftList.SetSelectedTextColor(tcell.GetColor(ColorActive)).
		SetSelectedBackgroundColor(tcell.GetColor("#313244"))

	// 4. Middle Column: Details & Open Ports
	middleText := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true)
	borderStyle(middleText.Box, "PROPERTIES & OPEN PORTS")

	// 5. Right Column: Scope Metrics & Vulnerabilities
	rightText := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true)
	borderStyle(rightText.Box, "FINDINGS & VULNERABILITIES")

	// 6. Footer Help Bar
	footerHelp := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	footerHelp.SetText(fmt.Sprintf(
		" [%s]Keys:[-] Up/Down: Navigate scans  |  [%s]R[-] Refresh database  |  [%s]Q/Ctrl+C[-] Exit",
		ColorActive, ColorActive, ColorActive,
	))

	// 3-pane horizontal flex column layout
	mainFlex := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(leftList, 32, 1, true).
		AddItem(middleText, 42, 1, false).
		AddItem(rightText, 0, 1, false)

	// Screen layout vertical rows
	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(headerText, 1, 0, false).
		AddItem(topStats, 3, 0, false).
		AddItem(mainFlex, 0, 1, true).
		AddItem(footerHelp, 1, 0, false)

	// Keep track of fetched scans list to resolve indices
	var scansList []database.Scan

	// Function to reload data from database
	reloadData := func() {
		// System global statistics
		totalScans, _ := database.GetTotalScansCount()
		totalSubs, _ := database.GetTotalSubdomainsCount()
		totalPorts, _ := database.GetTotalPortsCount()
		totalVulns, _ := database.GetTotalVulnerabilitiesCount()

		statsText := fmt.Sprintf(
			" GLOBAL STATS: [%s]Scans ran:[-] [#cdd6f4]%d[-]    [%s]Domains found:[-] [#cdd6f4]%d[-]    [%s]Ports open:[-] [#cdd6f4]%d[-]    [%s]Vulnerabilities:[-] [#cdd6f4]%d[-]",
			ColorBlue, totalScans, ColorBlue, totalSubs, ColorBlue, totalPorts, ColorBlue, totalVulns,
		)
		topStats.SetText(statsText)

		// Recent 15 scans
		scans, err := database.GetRecentScans(15)
		if err != nil {
			middleText.SetText(fmt.Sprintf("[red]Database error: %v[-]", err))
			return
		}
		scansList = scans

		leftList.Clear()
		if len(scansList) == 0 {
			leftList.AddItem("No scans recorded.", "Run a scan first.", 0, nil)
			middleText.SetText("Select a scan run to view properties.")
			rightText.SetText("Select a scan to inspect findings.")
			return
		}

		for _, s := range scansList {
			statusSymbol := "[ ]"
			var statusColor string
			switch s.Status {
			case "completed":
				statusSymbol = "[+]"
				statusColor = ColorGreen
			case "failed":
				statusSymbol = "[-]"
				statusColor = ColorRed
			case "running":
				statusSymbol = "[*]"
				statusColor = ColorYellow
			case "cancelled":
				statusSymbol = "[ ]"
				statusColor = ColorBlue
			}

			age := time.Since(s.StartedAt).Round(time.Minute)
			ageStr := fmt.Sprintf("%dm ago", int(age.Minutes()))
			if age.Hours() >= 24 {
				ageStr = fmt.Sprintf("%.0fd ago", age.Hours()/24)
			} else if age.Hours() >= 1 {
				ageStr = fmt.Sprintf("%.0fh ago", age.Hours())
			}

			rowText := fmt.Sprintf("[%s]%s[-] #%d %s", statusColor, statusSymbol, s.ID, s.Target)
			leftList.AddItem(rowText, "Started "+ageStr, 0, nil)
		}
	}

	// Function to update details when scan is selected
	leftList.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		if index < 0 || index >= len(scansList) {
			return
		}
		s := scansList[index]

		// Update middle panel properties
		var midSB strings.Builder
		statusColor := ColorBlue
		switch s.Status {
		case "completed":
			statusColor = ColorGreen
		case "failed":
			statusColor = ColorRed
		case "running":
			statusColor = ColorYellow
		}
		statusBadge := fmt.Sprintf("[%s:black:b] %s [-]", statusColor, strings.ToUpper(s.Status))

		midSB.WriteString(fmt.Sprintf(" [%s:black:b]Target: %s[-]\n\n", ColorLavender, s.Target))
		midSB.WriteString(fmt.Sprintf(" %-12s %s\n", "Type:", strings.ToUpper(s.Type)))
		midSB.WriteString(fmt.Sprintf(" %-12s %s\n", "Status:", statusBadge))
		midSB.WriteString(fmt.Sprintf(" %-12s %s\n", "Started:", s.StartedAt.Format("15:04:05")))

		durStr := "Active..."
		if s.CompletedAt != nil {
			durStr = s.CompletedAt.Sub(s.StartedAt).Round(time.Second).String()
		} else if s.Status != "running" {
			durStr = "Unknown"
		} else {
			durStr = time.Since(s.StartedAt).Round(time.Second).String()
		}
		midSB.WriteString(fmt.Sprintf(" %-12s %s\n", "Duration:", durStr))
		midSB.WriteString(fmt.Sprintf(" [%s]Folder:[-] %s\n\n", ColorSubtle, s.ResultDir))

		// Render live running scan progress if applicable
		if s.Status == "running" {
			stateMgr := scan.NewManager(paths.StateDir())
			if state, err := stateMgr.LoadState(s.ID); err == nil {
				midSB.WriteString(fmt.Sprintf(" [%s:black:b]RUNTIME PROGRESS[-]\n", ColorYellow))
				completed := len(state.CompletedSteps)
				total := state.TotalSteps
				if total == 0 {
					total = 1
				}
				pct := float64(completed) / float64(total) * 100

				barWidth := 20
				filled := int(float64(barWidth) * pct / 100)
				bar := ""
				for i := 0; i < barWidth; i++ {
					if i < filled {
						bar += "█"
					} else {
						bar += "░"
					}
				}
				midSB.WriteString(fmt.Sprintf(" [%s]%.0f%%[-] Current: %d/%d steps\n", ColorYellow, pct, completed, total))
				if state.CurrentStep < len(scan.WildcardSteps) {
					midSB.WriteString(fmt.Sprintf(" Current: %s\n\n", scan.WildcardSteps[state.CurrentStep].Description))
				} else {
					midSB.WriteString(" Current: Finalizing...\n\n")
				}
			}
		}

		// List open ports
		midSB.WriteString(fmt.Sprintf(" [%s:black:b]DISCOVERED OPEN PORTS[-]\n", ColorSapphire))
		ports, err := database.GetPorts(s.ID)
		if err == nil && len(ports) > 0 {
			midSB.WriteString(fmt.Sprintf(" [%s]Host                Port/Proto  Service[-]\n", ColorSubtle))
			
			displayLimit := 8
			if len(ports) < displayLimit {
				displayLimit = len(ports)
			}
			for i := 0; i < displayLimit; i++ {
				p := ports[i]
				proto := p.Protocol
				if proto == "" {
					proto = "tcp"
				}
				portStr := fmt.Sprintf("%d/%s", p.Port, proto)
				srv := p.Service
				if srv == "" {
					srv = "unknown"
				}
				// Pad output cleanly using formatting tags
				midSB.WriteString(fmt.Sprintf(" %-19s %-11s %s\n", truncateText(p.Host, 18), portStr, truncateText(srv, 8)))
			}
			if len(ports) > displayLimit {
				midSB.WriteString(fmt.Sprintf(" [%s:black:i]...and %d more ports[-]\n", ColorSubtle, len(ports)-displayLimit))
			}
		} else {
			midSB.WriteString(fmt.Sprintf(" [%s]No open ports discovered.[-]\n", ColorSubtle))
		}
		middleText.SetText(midSB.String())

		// Update right panel findings
		var rightSB strings.Builder
		rightSB.WriteString(fmt.Sprintf(" [%s:black:b]SCOPE COUNTS[-]\n", ColorSapphire))
		stats, err := database.GetScanStats(s.ID)
		if err == nil && stats != nil {
			colSub := fmt.Sprintf("%d", stats.TotalSubdomains)
			colLive := fmt.Sprintf("%d", stats.LiveSubdomains)
			rightSB.WriteString(fmt.Sprintf(" %-14s [%s]%s[-]\n", "Subdomains:", ColorSapphire, colSub))
			rightSB.WriteString(fmt.Sprintf(" %-14s [%s]%s[-]\n\n", "Live Hosts:", ColorSapphire, colLive))
		} else {
			rightSB.WriteString(fmt.Sprintf(" [%s]No counters compiled.[-]\n\n", ColorSubtle))
		}

		// Vulnerability discoveries list
		rightSB.WriteString(fmt.Sprintf(" [%s:black:b]VULNERABILITY DISCOVERIES[-]\n", ColorActive))
		vulns, err := database.GetVulnerabilities(s.ID)
		if err == nil && len(vulns) > 0 {
			displayLimit := 10
			if len(vulns) < displayLimit {
				displayLimit = len(vulns)
			}
			for i := 0; i < displayLimit; i++ {
				v := vulns[i]
				var badge string
				switch strings.ToLower(v.Severity) {
				case "critical":
					badge = fmt.Sprintf("[%s][CRIT][-]", ColorRed)
				case "high":
					badge = fmt.Sprintf("[%s][HIGH][-]", ColorOrange)
				case "medium":
					badge = fmt.Sprintf("[%s][MED ][-]", ColorYellow)
				case "low":
					badge = fmt.Sprintf("[%s][LOW ][-]", ColorGreen)
				default:
					badge = fmt.Sprintf("[%s][INFO][-]", ColorBlue)
				}

				vTitle := truncateText(v.Name, 26)
				vHost := truncateText(v.Host, 14)
				rightSB.WriteString(fmt.Sprintf(" %s %s [%s]%s[-]\n", badge, vHost, ColorSubtle, vTitle))
			}
			if len(vulns) > displayLimit {
				rightSB.WriteString(fmt.Sprintf(" [%s:black:i]...and %d more vulnerabilities[-]\n", ColorSubtle, len(vulns)-displayLimit))
			}
		} else {
			rightSB.WriteString(fmt.Sprintf("\n [%s]Clean Scan - No vulnerabilities found.[-]\n", ColorGreen))
		}
		rightText.SetText(rightSB.String())
	})

	// Setup input captures (Global hotkeys)
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'q', 'Q':
			app.Stop()
			return nil
		case 'r', 'R':
			reloadData()
			// Focus first item
			if leftList.GetItemCount() > 0 {
				leftList.SetCurrentItem(0)
			}
			return nil
		}
		// Also support Escape and Ctrl+C to quit
		if event.Key() == tcell.KeyCtrlC || event.Key() == tcell.KeyEscape {
			app.Stop()
			return nil
		}
		return event
	})

	// Initial data reload
	reloadData()
	if leftList.GetItemCount() > 0 {
		leftList.SetCurrentItem(0)
	}

	// Draw full screen layout container
	if err := app.SetRoot(layout, true).EnableMouse(true).Run(); err != nil {
		return err
	}
	return nil
}

func truncateText(str string, limit int) string {
	if len(str) <= limit {
		return str
	}
	if limit <= 3 {
		return str[:limit]
	}
	return str[:limit-3] + "..."
}
