// Package tui holds the interactive terminal UI: the first-run wizard
// (charmbracelet/huh), the configure menu (bubbletea), and shared styles.
package tui

import "github.com/charmbracelet/lipgloss"

// Shared palette (256-color; renders well on Windows Terminal / modern conhost).
var (
	Accent = lipgloss.Color("42")  // green
	Blue   = lipgloss.Color("39")  // blue
	Gray   = lipgloss.Color("245") // gray
	Red    = lipgloss.Color("203") // soft red
	Yellow = lipgloss.Color("214") // amber
	Cyan   = lipgloss.Color("45")  // cyan
	Purple = lipgloss.Color("141") // purple (cursor) — distinct from green OK

	TitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(Blue).Padding(0, 2)
	SubTitle     = lipgloss.NewStyle().Bold(true).Foreground(Cyan)
	LabelStyle   = lipgloss.NewStyle().Foreground(Gray)
	OKStyle      = lipgloss.NewStyle().Foreground(Accent).Bold(true)
	ErrStyle     = lipgloss.NewStyle().Foreground(Red).Bold(true)
	CursorStyle  = lipgloss.NewStyle().Foreground(Purple).Bold(true)
	DimStyle     = lipgloss.NewStyle().Foreground(Gray)
	PrimaryBadge = lipgloss.NewStyle().Foreground(Accent).Bold(true)
	YellowStyle  = lipgloss.NewStyle().Foreground(Yellow)
)

// Banner returns the styled program header used across screens.
func Banner() string {
	return TitleStyle.Render("--- Zeus_DNS-CLI ---")
}
