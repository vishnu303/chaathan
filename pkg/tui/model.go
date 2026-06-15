package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/paths"
	"github.com/vishnu303/chaathan/pkg/scan"
)

type model struct {
	scans         []database.Scan
	selectedIndex int
	err           error

	// System total stats
	totalScans int
	totalSubs  int
	totalPorts int
	totalVulns int

	// Selected scan metrics and findings
	selectedStats *database.ScanStats
	selectedVulns []database.Vulnerability
	selectedPorts []database.Port
	activeState   *scan.State

	width   int
	height  int
	loading bool
}

func initialModel() model {
	m := model{
		selectedIndex: 0,
		width:         110,
		height:        28,
	}
	m.loadData()
	return m
}

func (m *model) loadData() {
	m.loading = true

	// Load overall system counters
	m.totalScans, _ = database.GetTotalScansCount()
	m.totalSubs, _ = database.GetTotalSubdomainsCount()
	m.totalPorts, _ = database.GetTotalPortsCount()
	m.totalVulns, _ = database.GetTotalVulnerabilitiesCount()

	// Load recent 15 scans
	scans, err := database.GetRecentScans(15)
	if err != nil {
		m.err = err
		m.loading = false
		return
	}
	m.scans = scans

	if m.selectedIndex >= len(m.scans) {
		m.selectedIndex = 0
	}

	m.loadSelectedScanStats()
	m.loading = false
}

func (m *model) loadSelectedScanStats() {
	if len(m.scans) == 0 || m.selectedIndex < 0 || m.selectedIndex >= len(m.scans) {
		m.selectedStats = nil
		m.selectedVulns = nil
		m.selectedPorts = nil
		m.activeState = nil
		return
	}
	scanItem := m.scans[m.selectedIndex]

	// 1. Get counts
	stats, err := database.GetScanStats(scanItem.ID)
	if err == nil {
		m.selectedStats = stats
	}

	// 2. Get vulnerabilities
	vulns, err := database.GetVulnerabilities(scanItem.ID)
	if err == nil {
		m.selectedVulns = vulns
	} else {
		m.selectedVulns = nil
	}

	// 3. Get open ports
	ports, err := database.GetPorts(scanItem.ID)
	if err == nil {
		m.selectedPorts = ports
	} else {
		m.selectedPorts = nil
	}

	// 4. Check if currently running and load live state file
	if scanItem.Status == "running" {
		stateMgr := scan.NewManager(paths.StateDir())
		state, err := stateMgr.LoadState(scanItem.ID)
		if err == nil {
			m.activeState = state
		} else {
			m.activeState = nil
		}
	} else {
		m.activeState = nil
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up", "k":
			if len(m.scans) > 0 {
				m.selectedIndex--
				if m.selectedIndex < 0 {
					m.selectedIndex = len(m.scans) - 1
				}
				m.loadSelectedScanStats()
			}
		case "down", "j":
			if len(m.scans) > 0 {
				m.selectedIndex++
				if m.selectedIndex >= len(m.scans) {
					m.selectedIndex = 0
				}
				m.loadSelectedScanStats()
			}
		case "r":
			m.loadData()
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}
	return m, nil
}

func (m model) View() string {
	var s strings.Builder

	// Calculate panel heights
	contentHeight := m.height - 11
	if contentHeight < 12 {
		contentHeight = 12
	}

	// 1. Header View
	headerContent := lipgloss.JoinHorizontal(
		lipgloss.Bottom,
		StyleTitle.Render(),
		"  ",
		StyleSubtitle.Render("v1.0.0 • Professional Recon Console"),
	)
	s.WriteString(StyleHeader.Width(m.width - 4).Render(headerContent) + "\n\n")

	if m.err != nil {
		s.WriteString(lipgloss.NewStyle().Foreground(ColorStatusFail).Bold(true).Render(fmt.Sprintf("❌ DB Connection Error: %v", m.err)) + "\n")
		s.WriteString("\nPress 'q' or Ctrl+C to exit.")
		return s.String()
	}

	// 2. Top Summary Metrics Bar
	statsText := fmt.Sprintf(
		"📊 GLOBAL STATS:  %s %d    %s %d    %s %d    %s %d",
		StyleTopStat.Render("Scans Ran:"), m.totalScans,
		StyleTopStat.Render("Domains found:"), m.totalSubs,
		StyleTopStat.Render("Ports open:"), m.totalPorts,
		StyleTopStat.Render("Vulnerabilities:"), m.totalVulns,
	)
	s.WriteString(StyleTopBar.Width(m.width - 8).Render(statsText) + "\n\n")

	// Calculate column layout widths
	leftWidth := int(float64(m.width) * 0.28)
	if leftWidth < 30 {
		leftWidth = 30
	}
	middleWidth := int(float64(m.width) * 0.35)
	if middleWidth < 36 {
		middleWidth = 36
	}
	rightWidth := m.width - leftWidth - middleWidth - 8
	if rightWidth < 36 {
		rightWidth = 36
	}

	// --- Left Pane: Scan Runs List ---
	var listContent strings.Builder
	listContent.WriteString(StylePanelTitle.Render("📂 SCAN HISTORIC RUNS") + "\n")

	if len(m.scans) == 0 {
		listContent.WriteString(StyleSummaryValue.Copy().Foreground(ColorSubtle).Render("No runs recorded.\nStart a scan first.") + "\n")
	} else {
		for i, scanItem := range m.scans {
			statusSymbol := "⚫"
			statusStyle := lipgloss.NewStyle().Bold(true)
			switch scanItem.Status {
			case "completed":
				statusSymbol = "🟢"
				statusStyle = statusStyle.Foreground(ColorStatusDone)
			case "failed":
				statusSymbol = "🔴"
				statusStyle = statusStyle.Foreground(ColorStatusFail)
			case "running":
				statusSymbol = "🟡"
				statusStyle = statusStyle.Foreground(ColorStatusRun)
			case "cancelled":
				statusSymbol = "🔵"
				statusStyle = statusStyle.Foreground(ColorStatusIdle)
			}

			age := time.Since(scanItem.StartedAt).Round(time.Minute)
			ageStr := fmt.Sprintf("%dm ago", int(age.Minutes()))
			if age.Hours() >= 24 {
				ageStr = fmt.Sprintf("%.0fd ago", age.Hours()/24)
			} else if age.Hours() >= 1 {
				ageStr = fmt.Sprintf("%.0fh ago", age.Hours())
			}

			// Format row text nicely
			rowText := fmt.Sprintf("%s #%-3d %-12s %-4s", statusSymbol, scanItem.ID, truncate(scanItem.Target, 12), ageStr)

			if i == m.selectedIndex {
				listContent.WriteString(StyleScanRowSelected.Render(rowText) + "\n")
			} else {
				listContent.WriteString(StyleScanRow.Render(rowText) + "\n")
			}
		}
	}
	leftPanel := StylePanelMantleActive.Width(leftWidth).Height(contentHeight).Render(listContent.String())

	// --- Middle Pane: Scan Properties & Open Ports ---
	var midContent strings.Builder
	midContent.WriteString(StylePanelTitle.Render("📋 PROPERTIES & OPEN PORTS") + "\n")

	if len(m.scans) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.scans) {
		scanItem := m.scans[m.selectedIndex]

		// Status Badge
		statusColor := ColorStatusIdle
		switch scanItem.Status {
		case "completed":
			statusColor = ColorStatusDone
		case "failed":
			statusColor = ColorStatusFail
		case "running":
			statusColor = ColorStatusRun
		}
		statusBadge := lipgloss.NewStyle().Background(statusColor).Foreground(lipgloss.Color("#11111b")).Bold(true).Padding(0, 1).Render(strings.ToUpper(scanItem.Status))

		age := time.Since(scanItem.StartedAt).Round(time.Minute)
		ageStr := fmt.Sprintf("%dm ago", int(age.Minutes()))
		if age.Hours() >= 24 {
			ageStr = fmt.Sprintf("%.0fd ago", age.Hours()/24)
		} else if age.Hours() >= 1 {
			ageStr = fmt.Sprintf("%.0fh ago", age.Hours())
		}

		midContent.WriteString(fmt.Sprintf("%s\n\n", lipgloss.NewStyle().Foreground(ColorLavender).Bold(true).Render(scanItem.Target)))
		midContent.WriteString(fmt.Sprintf("%-12s %s\n", "Type:", StyleSummaryValue.Render(strings.ToUpper(scanItem.Type))))
		midContent.WriteString(fmt.Sprintf("%-12s %s\n", "Status:", statusBadge))
		midContent.WriteString(fmt.Sprintf("%-12s %s (%s)\n", "Started:", StyleSummaryValue.Render(scanItem.StartedAt.Format("15:04:05")), ageStr))

		durStr := "Active..."
		if scanItem.CompletedAt != nil {
			durStr = scanItem.CompletedAt.Sub(scanItem.StartedAt).Round(time.Second).String()
		} else if scanItem.Status != "running" {
			durStr = "Unknown"
		} else {
			durStr = time.Since(scanItem.StartedAt).Round(time.Second).String()
		}
		midContent.WriteString(fmt.Sprintf("%-12s %s\n", "Duration:", StyleSummaryValue.Render(durStr)))
		midContent.WriteString(fmt.Sprintf("%-12s %s\n\n", "Folder:", StyleSummaryValue.Copy().Foreground(ColorSubtle).Render(truncate(scanItem.ResultDir, middleWidth-16))))

		// 1. Live scan steps progress if running
		if scanItem.Status == "running" && m.activeState != nil {
			midContent.WriteString(lipgloss.NewStyle().Foreground(ColorStatusRun).Bold(true).Render("⏳ RUNTIME PROGRESS") + "\n")
			completed := len(m.activeState.CompletedSteps)
			total := m.activeState.TotalSteps
			if total == 0 {
				total = 1
			}
			pct := float64(completed) / float64(total) * 100

			barWidth := middleWidth - 14
			if barWidth < 10 {
				barWidth = 10
			}
			filled := int(float64(barWidth) * pct / 100)
			bar := ""
			for i := 0; i < barWidth; i++ {
				if i < filled {
					bar += "█"
				} else {
					bar += "░"
				}
			}
			midContent.WriteString(fmt.Sprintf("[%s] %.0f%%\n", bar, pct))
			
			// Show next/current step
			if m.activeState.CurrentStep < len(scan.WildcardSteps) {
				stepDesc := scan.WildcardSteps[m.activeState.CurrentStep].Description
				midContent.WriteString(fmt.Sprintf("Current: %s\n\n", StyleSummaryValue.Render(stepDesc)))
			} else {
				midContent.WriteString("Current: Finalizing...\n\n")
			}
		}

		// 2. Open Ports List
		midContent.WriteString(lipgloss.NewStyle().Foreground(ColorSapphire).Bold(true).Render("🔌 DISCOVERED OPEN PORTS") + "\n")
		if len(m.selectedPorts) > 0 {
			// Print header
			midContent.WriteString(lipgloss.NewStyle().Foreground(ColorSubtle).Render("Host                Port/Proto  Service") + "\n")
			
			// Limit to first 6 entries to avoid wrapping/scrolling issues
			displayLimit := 6
			if len(m.selectedPorts) < displayLimit {
				displayLimit = len(m.selectedPorts)
			}
			
			for i := 0; i < displayLimit; i++ {
				p := m.selectedPorts[i]
				proto := p.Protocol
				if proto == "" {
					proto = "tcp"
				}
				portStr := fmt.Sprintf("%d/%s", p.Port, proto)
				srv := p.Service
				if srv == "" {
					srv = "unknown"
				}
				midContent.WriteString(fmt.Sprintf("%-19s %-11s %s\n", truncate(p.Host, 18), portStr, truncate(srv, 8)))
			}
			if len(m.selectedPorts) > displayLimit {
				midContent.WriteString(lipgloss.NewStyle().Foreground(ColorSubtle).Italic(true).Render(fmt.Sprintf("...and %d more ports", len(m.selectedPorts)-displayLimit)) + "\n")
			}
		} else {
			midContent.WriteString(lipgloss.NewStyle().Foreground(ColorSubtle).Render("No open ports discovered.") + "\n")
		}
	} else {
		midContent.WriteString(StyleSummaryValue.Copy().Foreground(ColorSubtle).Render("Select a scan run to view properties.") + "\n")
	}
	middlePanel := StylePanel.Width(middleWidth).Height(contentHeight).Render(midContent.String())

	// --- Right Pane: Counts & Vulnerability Findings ---
	var rightContent strings.Builder
	rightContent.WriteString(StylePanelTitle.Render("⚡ FINDINGS & VULNERABILITIES") + "\n")

	if len(m.scans) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.scans) {
		// Target summary counts
		if m.selectedStats != nil {
			colSub := fmt.Sprintf("%d", m.selectedStats.TotalSubdomains)
			colLive := fmt.Sprintf("%d", m.selectedStats.LiveSubdomains)

			rightContent.WriteString(fmt.Sprintf("🌐 %-14s %s\n", "Subdomains:", StyleMetricVal.Render(colSub)))
			rightContent.WriteString(fmt.Sprintf("🖥️ %-14s %s\n\n", "Live Hosts:", StyleMetricVal.Render(colLive)))
		}

		// Vulnerabilities list breakdown
		rightContent.WriteString(lipgloss.NewStyle().Foreground(ColorMauve).Bold(true).Render("🔥 VULNERABILITY DISCOVERIES") + "\n")
		if len(m.selectedVulns) > 0 {
			// Limit to first 8 entries to avoid text clipping
			displayLimit := 8
			if len(m.selectedVulns) < displayLimit {
				displayLimit = len(m.selectedVulns)
			}
			
			for i := 0; i < displayLimit; i++ {
				v := m.selectedVulns[i]
				var badge string
				switch strings.ToLower(v.Severity) {
				case "critical":
					badge = StyleVulnCritical.Render("CRIT")
				case "high":
					badge = StyleVulnHigh.Render("HIGH")
				case "medium":
					badge = StyleVulnMedium.Render("MED ")
				case "low":
					badge = StyleVulnLow.Render("LOW ")
				default:
					badge = StyleVulnInfo.Render("INFO")
				}

				vTitle := truncate(v.Name, rightWidth-24)
				vHost := truncate(v.Host, 16)
				row := StyleVulnRow.Render(fmt.Sprintf("%s %s %s", badge, vHost, lipgloss.NewStyle().Foreground(ColorSubtle).Render(vTitle)))
				rightContent.WriteString(row + "\n")
			}
			
			if len(m.selectedVulns) > displayLimit {
				rightContent.WriteString(lipgloss.NewStyle().Foreground(ColorSubtle).Italic(true).Render(fmt.Sprintf("...and %d more vulnerabilities", len(m.selectedVulns)-displayLimit)) + "\n")
			}
		} else {
			rightContent.WriteString("\n" + lipgloss.NewStyle().Foreground(ColorStatusDone).Bold(true).Render("  ✅ Clean Scan - No vulnerabilities found.") + "\n")
		}
	} else {
		rightContent.WriteString(StyleSummaryValue.Copy().Foreground(ColorSubtle).Render("Select a scan to inspect findings.") + "\n")
	}
	rightPanel := StylePanel.Width(rightWidth).Height(contentHeight).Render(rightContent.String())

	// Join panels horizontally
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, middlePanel, rightPanel) + "\n\n")

	// 5. Footer View
	footerText := fmt.Sprintf(
		"🧭 %s Navigate list  •  🔄 %s Refresh database  •  🛑 %s Exit console",
		StyleKey.Render("↑/↓/j/k"),
		StyleKey.Render("r"),
		StyleKey.Render("q/Ctrl+C"),
	)
	s.WriteString(StyleFooter.Render(footerText))

	return s.String()
}

func truncate(str string, limit int) string {
	if len(str) <= limit {
		return str
	}
	if limit <= 3 {
		return str[:limit]
	}
	return str[:limit-3] + "..."
}
