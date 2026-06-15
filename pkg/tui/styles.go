package tui

import "github.com/charmbracelet/lipgloss"

// Color definitions (Catppuccin Mocha Palette)
var (
	ColorBase     = lipgloss.Color("#1e1e2e") // Main background
	ColorMantle   = lipgloss.Color("#181825") // Left sidebar panel
	ColorSurface  = lipgloss.Color("#313244") // Highlighted cards
	ColorBorder   = lipgloss.Color("#45475a") // Subtle grey borders
	ColorBorderAc = lipgloss.Color("#cba6f7") // Mauve (Active border accent)

	// Accents
	ColorLavender = lipgloss.Color("#b4befe") // Soft purple
	ColorMauve    = lipgloss.Color("#cba6f7") // Warm purple
	ColorSapphire = lipgloss.Color("#74c7ec") // Bright sky blue
	ColorPeach    = lipgloss.Color("#fab387") // Orange/Peach
	ColorText     = lipgloss.Color("#cdd6f4") // High contrast text
	ColorSubtle   = lipgloss.Color("#a6adc8") // Muted subtext

	// Status Colors
	ColorStatusDone = lipgloss.Color("#a6e3a1") // Catppuccin Green
	ColorStatusFail = lipgloss.Color("#f38ba8") // Catppuccin Red
	ColorStatusRun  = lipgloss.Color("#f9e2af") // Catppuccin Yellow
	ColorStatusIdle = lipgloss.Color("#89b4fa") // Catppuccin Blue

	// Severity Badges (Text foreground / Background pills)
	ColorCriticalBg = lipgloss.Color("#f38ba8")
	ColorHighBg     = lipgloss.Color("#fab387")
	ColorMediumBg   = lipgloss.Color("#f9e2af")
	ColorLowBg      = lipgloss.Color("#a6e3a1")
	ColorInfoBg     = lipgloss.Color("#89b4fa")
)

// Style definitions
var (
	// Header Section Styles
	StyleHeader = lipgloss.NewStyle().
			Foreground(ColorText).
			Background(ColorMantle).
			Padding(1, 2).
			Bold(true).
			Border(lipgloss.DoubleBorder(), false, false, true, false).
			BorderForeground(ColorMauve)

	StyleTitle = lipgloss.NewStyle().
			Foreground(ColorMauve).
			Bold(true).
			SetString("⚡ CHAATHAN SECURITY ORCHESTRATOR")

	StyleSubtitle = lipgloss.NewStyle().
			Foreground(ColorSapphire).
			Italic(true)

	// Top Summary Bar Card Styles
	StyleTopBar = lipgloss.NewStyle().
			Background(ColorMantle).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(0, 2).
			MarginBottom(1)

	StyleTopStat = lipgloss.NewStyle().
			Foreground(ColorSubtle)

	StyleTopValue = lipgloss.NewStyle().
			Foreground(ColorLavender).
			Bold(true)

	// Panel Columns
	StylePanel = lipgloss.NewStyle().
			Background(ColorBase).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(1, 2).
			MarginRight(1)

	StylePanelActive = StylePanel.
				Background(ColorBase).
				BorderForeground(ColorBorderAc)

	StylePanelMantle = StylePanel.
				Background(ColorMantle).
				BorderForeground(ColorBorder)

	StylePanelMantleActive = StylePanelMantle.
				BorderForeground(ColorBorderAc)

	StylePanelTitle = lipgloss.NewStyle().
			Foreground(ColorSapphire).
			Bold(true).
			MarginBottom(1).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(ColorBorder)

	// Scan Row List Styles
	StyleScanRow = lipgloss.NewStyle().
			Foreground(ColorText).
			Padding(0, 1)

	StyleScanRowSelected = lipgloss.NewStyle().
				Background(ColorSurface).
				Foreground(ColorMauve).
				Bold(true).
				Padding(0, 1)

	// Configuration Options Badges / Pills
	StyleConfigLabel = lipgloss.NewStyle().
				Foreground(ColorSubtle).
				Width(14)

	StyleConfigVal = lipgloss.NewStyle().
			Foreground(ColorText).
			Bold(true)

	StyleConfigPillTrue = lipgloss.NewStyle().
				Foreground(ColorStatusDone).
				Bold(true)

	StyleConfigPillFalse = lipgloss.NewStyle().
				Foreground(ColorStatusFail).
				Bold(true)

	// Metrics Layout Card Styles
	StyleMetricCard = lipgloss.NewStyle().
			Background(ColorSurface).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(0, 1).
			Width(18).
			Align(lipgloss.Center)

	StyleMetricVal = lipgloss.NewStyle().
			Foreground(ColorSapphire).
			Bold(true)

	StyleMetricLabel = lipgloss.NewStyle().
				Foreground(ColorSubtle).
				Width(16)

	StyleSummaryLabel = lipgloss.NewStyle().
				Foreground(ColorSubtle).
				Width(14)

	StyleSummaryValue = lipgloss.NewStyle().
				Foreground(ColorText).
				Bold(true)

	// Vulnerability Badges inside lists
	StyleVulnCritical = lipgloss.NewStyle().Background(ColorCriticalBg).Foreground(lipgloss.Color("#11111b")).Bold(true).Padding(0, 1)
	StyleVulnHigh     = lipgloss.NewStyle().Background(ColorHighBg).Foreground(lipgloss.Color("#11111b")).Bold(true).Padding(0, 1)
	StyleVulnMedium   = lipgloss.NewStyle().Background(ColorMediumBg).Foreground(lipgloss.Color("#11111b")).Bold(true).Padding(0, 1)
	StyleVulnLow      = lipgloss.NewStyle().Background(ColorLowBg).Foreground(lipgloss.Color("#11111b")).Bold(true).Padding(0, 1)
	StyleVulnInfo     = lipgloss.NewStyle().Background(ColorInfoBg).Foreground(lipgloss.Color("#11111b")).Bold(true).Padding(0, 1)

	StyleVulnRow = lipgloss.NewStyle().
			Foreground(ColorText).
			Padding(0, 0)

	// Footer Help Style
	StyleFooter = lipgloss.NewStyle().
			Foreground(ColorSubtle).
			Padding(0, 2).
			MarginTop(1)

	StyleKey = lipgloss.NewStyle().
			Foreground(ColorMauve).
			Bold(true)
)
