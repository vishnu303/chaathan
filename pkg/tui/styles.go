package tui

import "github.com/charmbracelet/lipgloss"

// Color definitions (Harmonious Dark Theme)
var (
	ColorBg          = lipgloss.Color("#181825") // Base dark charcoal
	ColorBgCard      = lipgloss.Color("#1E1E2E") // Slightly lighter dark grey for cards
	ColorBorder      = lipgloss.Color("#313244") // Subtle divider grey
	ColorAccent      = lipgloss.Color("#7D56F4") // Neon Purple (primary brand)
	ColorCyan        = lipgloss.Color("#00F0FF") // Electric Cyan (secondary brand)
	ColorSubtle      = lipgloss.Color("#A6ADC8") // Muted grey for descriptions
	ColorText        = lipgloss.Color("#CDD6F4") // Main white/grey text

	// Status Colors
	ColorStatusDone  = lipgloss.Color("#00FF87") // Vibrant Green
	ColorStatusFail  = lipgloss.Color("#FF0055") // Neon Red/Pink
	ColorStatusRun   = lipgloss.Color("#FFB300") // Warm Amber
	ColorStatusIdle  = lipgloss.Color("#89B4FA") // Cool Blue

	// Severity Colors
	ColorCritical    = lipgloss.Color("#F38BA8") // Pastel Red
	ColorHigh        = lipgloss.Color("#FAB387") // Pastel Orange
	ColorMedium      = lipgloss.Color("#F9E2AF") // Pastel Yellow
	ColorLow         = lipgloss.Color("#A6E3A1") // Pastel Green
	ColorInfo        = lipgloss.Color("#89B4FA") // Pastel Blue
)

// Style definitions
var (
	// Header Section Styles
	StyleHeader = lipgloss.NewStyle().
			Foreground(ColorText).
			Background(ColorBgCard).
			Padding(1, 2).
			Bold(true).
			Border(lipgloss.RoundedBorder(), false, false, true, false).
			BorderForeground(ColorAccent)

	StyleTitle = lipgloss.NewStyle().
			Foreground(ColorAccent).
			Bold(true).
			SetString("CHAATHAN PENTESTING ORCHESTRATOR")

	StyleSubtitle = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Italic(true)

	// Column / Panel Layouts
	StylePanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(1, 2).
			MarginRight(1)

	StylePanelActive = StylePanel.
				BorderForeground(ColorAccent)

	StylePanelTitle = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true).
			MarginBottom(1)

	// Scan List Styles
	StyleScanRow = lipgloss.NewStyle().
			Padding(0, 1)

	StyleScanRowSelected = lipgloss.NewStyle().
				Background(ColorAccent).
				Foreground(lipgloss.Color("#FFFFFF")).
				Bold(true).
				Padding(0, 1)

	// Detail View Card / Metrics Styles
	StyleMetricCard = lipgloss.NewStyle().
			Background(ColorBgCard).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(0, 1).
			Width(22).
			Align(lipgloss.Center)

	StyleMetricVal = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true)

	StyleMetricLabel = lipgloss.NewStyle().
				Foreground(ColorSubtle)

	// Vulnerability Badges
	StyleVulnCritical = lipgloss.NewStyle().Foreground(ColorCritical).Bold(true)
	StyleVulnHigh     = lipgloss.NewStyle().Foreground(ColorHigh).Bold(true)
	StyleVulnMedium   = lipgloss.NewStyle().Foreground(ColorMedium).Bold(true)
	StyleVulnLow      = lipgloss.NewStyle().Foreground(ColorLow).Bold(true)
	StyleVulnInfo     = lipgloss.NewStyle().Foreground(ColorInfo).Bold(true)

	// System Overview Summary Style
	StyleSummaryLabel = lipgloss.NewStyle().Foreground(ColorSubtle).Width(16)
	StyleSummaryValue = lipgloss.NewStyle().Foreground(ColorText).Bold(true)

	// Footer Help Style
	StyleFooter = lipgloss.NewStyle().
			Foreground(ColorSubtle).
			Padding(0, 2).
			MarginTop(1)

	StyleKey = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true)
)
