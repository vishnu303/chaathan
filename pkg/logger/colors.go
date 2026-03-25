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
