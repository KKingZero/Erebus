package theme

import "github.com/charmbracelet/lipgloss"

// Crimson is used for UI accents only (borders, chrome, active states).
const Crimson = "#DC143C"

// ANSICrimson accents the erebus prompt in the plain REPL.
const (
	ANSIReset   = "\033[0m"
	ANSICrimson = "\033[1;38;5;196m"
)

var (
	crimson = lipgloss.Color(Crimson)

	// Default — terminal foreground, no override.
	Default = lipgloss.NewStyle()

	// Accent — crimson for headers, labels, prompts inside the TUI.
	Accent = lipgloss.NewStyle().Foreground(crimson).Bold(true)

	AccentPlain = lipgloss.NewStyle().Foreground(crimson)

	// Border accents only.
	Border = lipgloss.NewStyle().BorderForeground(crimson)

	Box = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(crimson).
		Padding(0, 1)

	Active   = Accent
	Inactive = Default
)