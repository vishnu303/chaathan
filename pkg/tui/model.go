package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vishnu303/chaathan/pkg/database"
)

type model struct {
	scans         []database.Scan
	selectedIndex int
	err           error

	// System total counters
	totalScans int
	totalSubs  int
	totalPorts int
	totalVulns int

	// Selected scan metrics
	selectedStats *database.ScanStats

	width  int
	height int

	// Refresh interval indicator
	loading bool
}

func initialModel() model {
	m := model{
		selectedIndex: 0,
		width:         80,
		height:        24,
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
		return
	}
	scanItem := m.scans[m.selectedIndex]
	stats, err := database.GetScanStats(scanItem.ID)
	if err == nil {
		m.selectedStats = stats
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

	// 1. Header View
	headerContent := lipgloss.JoinHorizontal(
		lipgloss.Bottom,
		StyleTitle.Render(),
		"  ",
		StyleSubtitle.Render("v1.0.0 • Live Dashboard"),
	)
	s.WriteString(StyleHeader.Width(m.width - 4).Render(headerContent) + "\n\n")

	if m.err != nil {
		s.WriteString(lipgloss.NewStyle().Foreground(ColorStatusFail).Bold(true).Render(fmt.Sprintf("Database Error: %v", m.err)) + "\n")
		s.WriteString("\nPress 'q' or Ctrl+C to exit.")
		return s.String()
	}

	// Calculate layouts based on terminal size
	contentHeight := m.height - 8
	if contentHeight < 10 {
		contentHeight = 10
	}

	leftWidth := int(float64(m.width) * 0.45)
	if leftWidth < 35 {
		leftWidth = 35
	}
	rightWidth := m.width - leftWidth - 6
	if rightWidth < 35 {
		rightWidth = 35
	}

	// 2. Left Panel: Scan List
	var listContent strings.Builder
	listContent.WriteString(StylePanelTitle.Render("Recent Runs") + "\n")

	if len(m.scans) == 0 {
		listContent.WriteString(StyleSummaryValue.Copy().Foreground(ColorSubtle).Render("No scans recorded yet.\nRun a wildcard scan to start.") + "\n")
	} else {
		for i, scanItem := range m.scans {
			statusSymbol := "⚪"
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

			// Format row text
			age := time.Since(scanItem.StartedAt).Round(time.Minute)
			ageStr := fmt.Sprintf("%dm ago", int(age.Minutes()))
			if age.Hours() >= 24 {
				ageStr = fmt.Sprintf("%.0fd ago", age.Hours()/24)
			} else if age.Hours() >= 1 {
				ageStr = fmt.Sprintf("%.0fh ago", age.Hours())
			}

			rowText := fmt.Sprintf("%s  #%-3d %-18s %-4s", statusSymbol, scanItem.ID, truncate(scanItem.Target, 18), ageStr)

			if i == m.selectedIndex {
				listContent.WriteString(StyleScanRowSelected.Width(leftWidth - 4).Render(rowText) + "\n")
			} else {
				listContent.WriteString(StyleScanRow.Render(rowText) + "\n")
			}
		}
	}

	// Wrap in left panel container
	leftPanel := StylePanelActive.Width(leftWidth).Height(contentHeight).Render(listContent.String())

	// 3. Right Panel: Scan details & Metrics
	var detailContent strings.Builder

	if len(m.scans) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.scans) {
		scanItem := m.scans[m.selectedIndex]

		// Format Title
		detailContent.WriteString(StylePanelTitle.Render(fmt.Sprintf("Scan Details: %s", scanItem.Target)) + "\n\n")

		// System Status Badge & General Details
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

		detailContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Workflow Type:"), StyleSummaryValue.Render(strings.ToUpper(scanItem.Type))))
		detailContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Status:"), statusBadge))
		detailContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Started:"), StyleSummaryValue.Render(scanItem.StartedAt.Format("2006-01-02 15:04:05"))))

		durationStr := "Active..."
		if scanItem.CompletedAt != nil {
			dur := scanItem.CompletedAt.Sub(scanItem.StartedAt).Round(time.Second)
			durationStr = dur.String()
		} else if scanItem.Status != "running" {
			durationStr = "Unknown"
		} else {
			dur := time.Since(scanItem.StartedAt).Round(time.Second)
			durationStr = dur.String()
		}
		detailContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Duration:"), StyleSummaryValue.Render(durationStr)))
		detailContent.WriteString(fmt.Sprintf("%s %s\n\n", StyleSummaryLabel.Render("Result Folder:"), StyleSummaryValue.Copy().Foreground(ColorSubtle).Render(truncate(scanItem.ResultDir, rightWidth-18))))

		// Metrics Grid Cards
		if m.selectedStats != nil {
			detailContent.WriteString(lipgloss.NewStyle().Foreground(ColorCyan).Bold(true).Render("SCAN METRICS") + "\n")
			card1 := StyleMetricCard.Render(fmt.Sprintf("%s\n%s", StyleMetricVal.Render(fmt.Sprintf("%d", m.selectedStats.TotalSubdomains)), StyleMetricLabel.Render("Subdomains")))
			card2 := StyleMetricCard.Render(fmt.Sprintf("%s\n%s", StyleMetricVal.Render(fmt.Sprintf("%d", m.selectedStats.LiveSubdomains)), StyleMetricLabel.Render("Live Hosts")))
			card3 := StyleMetricCard.Render(fmt.Sprintf("%s\n%s", StyleMetricVal.Render(fmt.Sprintf("%d", m.selectedStats.TotalPorts)), StyleMetricLabel.Render("Open Ports")))

			detailContent.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, card1, " ", card2, " ", card3) + "\n\n")

			// Vulnerabilities list breakdown
			detailContent.WriteString(lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Render("VULNERABILITIES FOUND") + "\n")
			v := m.selectedStats.Vulnerabilities

			critCount := v["critical"]
			highCount := v["high"]
			medCount := v["medium"]
			lowCount := v["low"]
			infoCount := v["info"]

			rowCrit := fmt.Sprintf("%s  %-12s %d", "🔴", StyleVulnCritical.Render("Critical:"), critCount)
			rowHigh := fmt.Sprintf("%s  %-12s %d", "🟠", StyleVulnHigh.Render("High:"), highCount)
			rowMed  := fmt.Sprintf("%s  %-12s %d", "🟡", StyleVulnMedium.Render("Medium:"), medCount)
			rowLow  := fmt.Sprintf("%s  %-12s %d", "🟢", StyleVulnLow.Render("Low:"), lowCount)
			rowInfo := fmt.Sprintf("%s  %-12s %d", "🔵", StyleVulnInfo.Render("Info:"), infoCount)

			detailContent.WriteString(lipgloss.JoinVertical(lipgloss.Left, rowCrit, rowHigh, rowMed, rowLow, rowInfo) + "\n")
		} else {
			detailContent.WriteString(StyleSummaryValue.Copy().Foreground(ColorSubtle).Render("No statistics compiled for this scan.") + "\n")
		}
	} else {
		detailContent.WriteString(StylePanelTitle.Render("System Summary") + "\n\n")
		detailContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Total Scans:"), StyleSummaryValue.Render(fmt.Sprintf("%d", m.totalScans))))
		detailContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Subdomains:"), StyleSummaryValue.Render(fmt.Sprintf("%d", m.totalSubs))))
		detailContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Open Ports:"), StyleSummaryValue.Render(fmt.Sprintf("%d", m.totalPorts))))
		detailContent.WriteString(fmt.Sprintf("%s %s\n", StyleSummaryLabel.Render("Vulnerabilities:"), StyleSummaryValue.Render(fmt.Sprintf("%d", m.totalVulns))))
	}

	rightPanel := StylePanel.Width(rightWidth).Height(contentHeight).Render(detailContent.String())

	// Join horizontally
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, rightPanel) + "\n\n")

	// 4. Footer View
	footerText := fmt.Sprintf(
		"%s navigate scans • %s refresh • %s exit",
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
	return str[:limit-3] + "..."
}
