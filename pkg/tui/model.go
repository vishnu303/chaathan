package tui

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vishnu303/chaathan/pkg/database"
)

type ScanConfig struct {
	SkipAmass       bool   `json:"skip_amass"`
	SkipNuclei      bool   `json:"skip_nuclei"`
	SkipNaabu       bool   `json:"skip_naabu"`
	SkipCrawl       bool   `json:"skip_crawl"`
	SkipTakeovers   bool   `json:"skip_takeovers"`
	SkipDalfox      bool   `json:"skip_dalfox"`
	SkipUncover     bool   `json:"skip_uncover"`
	SkipTlsx        bool   `json:"skip_tlsx"`
	SkipArjun       bool   `json:"skip_arjun"`
	SkipShuffleDNS  bool   `json:"skip_shuffledns"`
	SkipHakrawler   bool   `json:"skip_hakrawler"`
	SkipFingerprint bool   `json:"skip_fingerprint"`
	Wordlist        string `json:"wordlist"`
	DNSWordlist     string `json:"dns_wordlist"`
	GitHub          bool   `json:"github"`
	AutoProxy       bool   `json:"auto_proxy"`
}

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
	parsedConfig  *ScanConfig

	width  int
	height int
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
		m.parsedConfig = nil
		return
	}
	scanItem := m.scans[m.selectedIndex]

	// 1. Get counts
	stats, err := database.GetScanStats(scanItem.ID)
	if err == nil {
		m.selectedStats = stats
	}

	// 2. Get top 5 vulnerabilities
	vulns, err := database.GetVulnerabilities(scanItem.ID)
	if err == nil {
		if len(vulns) > 5 {
			m.selectedVulns = vulns[:5]
		} else {
			m.selectedVulns = vulns
		}
	} else {
		m.selectedVulns = nil
	}

	// 3. Parse scan options configurations
	if scanItem.Config != "" {
		var sc ScanConfig
		if err := json.Unmarshal([]byte(scanItem.Config), &sc); err == nil {
			m.parsedConfig = &sc
		} else {
			m.parsedConfig = nil
		}
	} else {
		m.parsedConfig = nil
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
				listContent.WriteString(StyleScanRowSelected.Width(leftWidth - 4).Render(rowText) + "\n")
			} else {
				listContent.WriteString(StyleScanRow.Render(rowText) + "\n")
			}
		}
	}
	leftPanel := StylePanelMantleActive.Width(leftWidth).Height(contentHeight).Render(listContent.String())

	// --- Middle Pane: Scan metadata & Config options ---
	var midContent strings.Builder
	midContent.WriteString(StylePanelTitle.Render("📋 METADATA & PARAMETERS") + "\n")

	if len(m.scans) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.scans) {
		scanItem := m.scans[m.selectedIndex]

		// Target Title & Status Pill
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

		midContent.WriteString(fmt.Sprintf("%s\n", lipgloss.NewStyle().Foreground(ColorLavender).Bold(true).Render(scanItem.Target)))
		midContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Type:"), StyleSummaryValue.Render(strings.ToUpper(scanItem.Type))))
		midContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Status:"), statusBadge))
		midContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Started:"), StyleSummaryValue.Render(scanItem.StartedAt.Format("2006-01-02 15:04:05"))))

		durStr := "Active..."
		if scanItem.CompletedAt != nil {
			durStr = scanItem.CompletedAt.Sub(scanItem.StartedAt).Round(time.Second).String()
		} else if scanItem.Status != "running" {
			durStr = "Unknown"
		} else {
			durStr = time.Since(scanItem.StartedAt).Round(time.Second).String()
		}
		midContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Duration:"), StyleSummaryValue.Render(durStr)))
		midContent.WriteString(fmt.Sprintf("%s %s\n\n", StyleSummaryLabel.Render("Output:"), StyleSummaryValue.Copy().Foreground(ColorSubtle).Render(truncate(scanItem.ResultDir, middleWidth-16))))

		// Config flags parsed from DB json
		midContent.WriteString(lipgloss.NewStyle().Foreground(ColorSapphire).Bold(true).Render("🛡️ SCAN ENGINE OPTION FLAGS") + "\n")
		if m.parsedConfig != nil {
			c := m.parsedConfig

			printPill := func(name string, active bool) string {
				valText := StyleConfigPillFalse.Render("Disabled")
				if active {
					valText = StyleConfigPillTrue.Render("Enabled")
				}
				return fmt.Sprintf("%s %s\n", StyleConfigLabel.Render(name), valText)
			}

			// Render config parameters status
			midContent.WriteString(printPill("Active DNS:", !c.SkipAmass))
			midContent.WriteString(printPill("Port Scanning:", !c.SkipNaabu))
			midContent.WriteString(printPill("Vulnerabilities:", !c.SkipNuclei))
			midContent.WriteString(printPill("Web Crawling:", !c.SkipCrawl))
			midContent.WriteString(printPill("XSS Audits:", !c.SkipDalfox))
			midContent.WriteString(printPill("Auto Proxy:", c.AutoProxy))

			wlText := StyleConfigPillFalse.Render("None")
			if c.Wordlist != "" {
				wlText = StyleConfigPillTrue.Render("Custom")
			}
			midContent.WriteString(fmt.Sprintf("%s %s\n", StyleConfigLabel.Render("Fuzzing Wordlist:"), wlText))
		} else {
			midContent.WriteString(StyleSummaryValue.Copy().Foreground(ColorSubtle).Render("No parameters available.") + "\n")
		}
	} else {
		midContent.WriteString(StyleSummaryValue.Copy().Foreground(ColorSubtle).Render("Select a scan run to view properties.") + "\n")
	}
	middlePanel := StylePanel.Width(middleWidth).Height(contentHeight).Render(midContent.String())

	// --- Right Pane: Counts & Recent Findings ---
	var rightContent strings.Builder
	rightContent.WriteString(StylePanelTitle.Render("⚡ SCOPE COUNTS & TOP FINDINGS") + "\n")

	if len(m.scans) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.scans) {
		// Metrics row
		if m.selectedStats != nil {
			colSub := fmt.Sprintf("%d", m.selectedStats.TotalSubdomains)
			colPrt := fmt.Sprintf("%d", m.selectedStats.TotalPorts)
			colLive := fmt.Sprintf("%d", m.selectedStats.LiveSubdomains)

			rowMetrics := fmt.Sprintf(
				"🌐 %s %s  •  🔌 %s %s  •  🖥️ %s %s\n\n",
				StyleMetricLabel.Render("Subs:"), StyleMetricVal.Render(colSub),
				StyleMetricLabel.Render("Ports:"), StyleMetricVal.Render(colPrt),
				StyleMetricLabel.Render("Live:"), StyleMetricVal.Render(colLive),
			)
			rightContent.WriteString(rowMetrics)
		}

		// Vulnerabilities list breakdown
		rightContent.WriteString(lipgloss.NewStyle().Foreground(ColorMauve).Bold(true).Render("🔥 RECENT CRITICAL DISCOVERIES") + "\n")
		if len(m.selectedVulns) > 0 {
			for _, v := range m.selectedVulns {
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
		} else {
			rightContent.WriteString("\n" + lipgloss.NewStyle().Foreground(ColorStatusDone).Bold(true).Render("  ✅ No vulnerabilities detected so far.") + "\n")
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
