package logger

// ColorStatus returns an ANSI-coloured string for a scan status value.
// Expected values: "completed", "running", "failed", "cancelled".
func ColorStatus(status string) string {
	switch status {
	case "completed":
		return BrightGreen + status + Reset
	case "running":
		return BrightYellow + status + Reset
	case "failed":
		return BrightRed + status + Reset
	case "cancelled":
		return Gray + status + Reset
	default:
		return status
	}
}

// EmojiStatus returns an emoji-prefixed status string for CLI table output.
func EmojiStatus(status string) string {
	switch status {
	case "completed":
		return "✅ completed"
	case "running":
		return "🔄 running"
	case "failed":
		return "❌ failed"
	case "cancelled":
		return "⚠️  cancelled"
	default:
		return status
	}
}

// ColorSeverity returns an ANSI-coloured string for a vulnerability severity.
// Expected values: "critical", "high", "medium", "low", "info".
func ColorSeverity(sev string) string {
	switch sev {
	case "critical":
		return BrightRed + sev + Reset
	case "high":
		return Red + sev + Reset
	case "medium":
		return Yellow + sev + Reset
	case "low":
		return Green + sev + Reset
	case "info":
		return Blue + sev + Reset
	default:
		return sev
	}
}

// EmojiSeverity returns an emoji-prefixed, uppercased severity label
// for CLI table output (e.g. "🔴 CRITICAL").
func EmojiSeverity(sev string) string {
	switch sev {
	case "critical":
		return "🔴 CRITICAL"
	case "high":
		return "🟠 HIGH"
	case "medium":
		return "🟡 MEDIUM"
	case "low":
		return "🟢 LOW"
	case "info":
		return "🔵 INFO"
	default:
		return sev
	}
}

