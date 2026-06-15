package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// StartDashboard launches the interactive terminal TUI dashboard in full screen
// buffer mode, returning terminal state to normal upon exit.
func StartDashboard() error {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
