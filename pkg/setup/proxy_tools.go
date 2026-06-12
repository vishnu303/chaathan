// Proxy Tools Installation
//
// Installs proxy automation tools:
// - mubeng: Go-based proxy IP rotator (installed via go install)
//
// mubeng is handled by the Go tools section (it has an InstallURL in the registry).
// This section is now a no-op but kept for architectural consistency.
package setup

// ─────────────────────────────────────────────────────────────
// installProxyToolsSection
// ─────────────────────────────────────────────────────────────

func installProxyToolsSection() (installed, skipped, failed int) {
	// mubeng is installed via the Go tools section.
	// We no longer install proxy-scraper-checker as it is replaced
	// by a native Go fetch + mubeng check implementation.
	return 0, 0, 0
}
