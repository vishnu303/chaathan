package logger

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// ── ANSI codes ───────────────────────────────────────────────────────────────

var (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Italic    = "\033[3m"
	Underline = "\033[4m"

	// Standard colors
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	Gray   = "\033[37m"
	White  = "\033[97m"

	// Bright colors
	BrightRed    = "\033[91m"
	BrightGreen  = "\033[92m"
	BrightYellow = "\033[93m"
	BrightBlue   = "\033[94m"
	BrightPurple = "\033[95m"
	BrightCyan   = "\033[96m"

	// Background
	BgRed    = "\033[41m"
	BgGreen  = "\033[42m"
	BgYellow = "\033[43m"
	BgBlue   = "\033[44m"
	BgCyan   = "\033[46m"
)

// ── Scan step tracking ──────────────────────────────────────────────────────

var (
	currentStep   int
	totalSteps    int
	scanStartTime time.Time
)

// InitScanUI initializes the scan UI with the total number of steps.
func InitScanUI(total int) {
	currentStep = 0
	totalSteps = total
	scanStartTime = time.Now()
}

// ── Primary output functions ────────────────────────────────────────────────

// Info prints a styled info message
func Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s│%s %s\n", Dim, Reset, msg)
}

// Success prints a styled success message
func Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s│%s %s✓%s %s\n", Dim, Reset, BrightGreen, Reset, msg)
}

// Warning prints a styled warning message
func Warning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s│%s %s⚠%s %s\n", Dim, Reset, BrightYellow, Reset, msg)
}

// Error prints a styled error message
func Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s│%s %s✗%s %s%s%s\n", Dim, Reset, BrightRed, Reset, Red, msg, Reset)
}

// Debug prints a styled debug message (only visible contextually)
func Debug(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s│  %s%s\n", Dim, msg, Reset)
}

// Section prints a generic section heading without incrementing the step counter.
// Use this in non-scan commands (status, diff, export, delete, query, etc.)
// that don't participate in the step-tracking workflow.
func Section(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("\n  %s┌─%s %s%s%s%s\n", Cyan, Reset, BrightCyan+Bold, msg, Reset, "")
}

// StepHeader prints a scan-step heading that increments the step counter
// and shows elapsed time. Use this only in scan workflow phases.
func StepHeader(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	currentStep++

	elapsed := ""
	if !scanStartTime.IsZero() {
		elapsed = fmt.Sprintf(" %s%s%s", Dim, fmtElapsed(time.Since(scanStartTime)), Reset)
	}

	stepIndicator := ""
	if totalSteps > 0 {
		stepIndicator = fmt.Sprintf("%s[%d/%d]%s ", Dim, currentStep, totalSteps, Reset)
	}

	fmt.Printf("\n  %s┌─%s %s%s%s%s%s%s\n", Cyan, Reset, stepIndicator, BrightCyan+Bold, msg, Reset, elapsed, "")
}

// ScanHeader prints the main scan workflow header
func ScanHeader(scanType string, target string, scanID int64) {
	w := 52
	line := strings.Repeat("─", w)

	fmt.Printf("\n")
	fmt.Printf("  %s╭%s╮%s\n", Cyan+Bold, line, Reset)
	// '  ' (2) + '🔍 ' (3) + 46 + ' ' (1) = 52
	fmt.Printf("  %s│%s  🔍 %s%-46s%s %s│%s\n", Cyan+Bold, Reset, White+Bold, scanType+" Scan", Reset, Cyan+Bold, Reset)
	// '  ' (2) + '🎯 ' (3) + 'Target:' (7) + ' ' (1) + 38 + ' ' (1) = 52
	fmt.Printf("  %s│%s  %s🎯 Target:%s %-38s %s│%s\n", Cyan+Bold, Reset, Dim, Reset, target, Cyan+Bold, Reset)
	if scanID > 0 {
		// '  ' (2) + '🆔 ' (3) + 'Scan ID:' (8) + ' ' (1) + 37 + ' ' (1) = 52
		fmt.Printf("  %s│%s  %s🆔 Scan ID:%s %-37d %s│%s\n", Cyan+Bold, Reset, Dim, Reset, scanID, Cyan+Bold, Reset)
	}
	fmt.Printf("  %s╰%s╯%s\n", Cyan+Bold, line, Reset)
	fmt.Printf("\n")
}

// SubStep prints an indented sub-step with arrow
func SubStep(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s│%s   %s▸%s %s\n", Dim, Reset, Purple, Reset, msg)
}

// Command prints the command being executed
func Command(cmd string) {
	fmt.Printf("  %s│     $ %s%s\n", Dim, cmd, Reset)
}

// ── Summary helpers ─────────────────────────────────────────────────────────

// ScanSummary prints a modern scan completion summary
func ScanSummary(status string, target string, scanID int64, duration time.Duration, stats map[string]string) {
	w := 52
	line := strings.Repeat("─", w)

	statusIcon := "✓"
	statusColor := BrightGreen
	switch status {
	case "cancelled":
		statusIcon = "⚠"
		statusColor = BrightYellow
	case "failed":
		statusIcon = "✗"
		statusColor = BrightRed
	}

	fmt.Printf("\n")
	fmt.Printf("  %s╭%s╮%s\n", Cyan+Bold, line, Reset)
	
	statusStr := capitalize(status)
	pad1 := w - 2 - 1 - 6 - len(statusStr) // '  ' (2), statusIcon (1), ' Scan ' (6)
	if pad1 < 0 { pad1 = 0 }
	fmt.Printf("  %s│%s  %s%s%s %sScan %s%s%s%s│%s\n",
		Cyan+Bold, Reset, statusColor+Bold, statusIcon, Reset,
		White+Bold, statusStr, Reset,
		strings.Repeat(" ", pad1), Cyan+Bold, Reset)

	pad2 := w - 2 - 2 - len(target) - 1 // '  ' (2), '🎯' (1/2), len(target), extra space. Assume '🎯 ' is 3 columns.
	pad2 = w - 5 - len(target)
	if pad2 < 0 { pad2 = 0 }
	fmt.Printf("  %s│%s  %s🎯 %s%s%s%s│%s\n", Cyan+Bold, Reset, Dim, target, Reset, strings.Repeat(" ", pad2), Cyan+Bold, Reset)

	durStr := fmtDuration(duration)
	pad3 := w - 6 - len(durStr) // '  ' (2) + '⏱  ' (4)
	if pad3 < 0 { pad3 = 0 }
	fmt.Printf("  %s│%s  %s⏱  %s%s%s%s│%s\n", Cyan+Bold, Reset, Dim, durStr, Reset, strings.Repeat(" ", pad3), Cyan+Bold, Reset)

	if len(stats) > 0 {
		fmt.Printf("  %s│%s  %s%s%s%s│%s\n", Cyan+Bold, Reset, Dim, strings.Repeat("╌", w-2), Reset, Cyan+Bold, Reset)
		for label, value := range stats {
			// '  ' (2) + len(label) + 1 + len(value)
			used := 2 + len(label) + 1 + len(value)
			padding := w - used
			if padding < 1 { padding = 1 }
			fmt.Printf("  %s│%s  %s%s%s %s%s%s%s %s│%s\n",
				Cyan+Bold, Reset,
				Dim, label+":", Reset,
				BrightCyan+Bold, value, Reset,
				strings.Repeat(" ", padding-1),
				Cyan+Bold, Reset)
		}
	}

	fmt.Printf("  %s╰%s╯%s\n", Cyan+Bold, line, Reset)
}

// NextSteps prints styled next step hints
func NextSteps(hints []string) {
	if len(hints) == 0 {
		return
	}
	fmt.Printf("\n  %s💡 Next steps:%s\n", Dim, Reset)
	for _, h := range hints {
		fmt.Printf("     %s▸%s %s%s%s\n", Purple, Reset, Dim, h, Reset)
	}
	fmt.Println()
}

// ── Utility ─────────────────────────────────────────────────────────────────

// capitalize returns the string with the first letter uppercased.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func fmtElapsed(d time.Duration) string {
	d = d.Round(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("[%dm%02ds]", m, s)
	}
	return fmt.Sprintf("[%ds]", s)
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
