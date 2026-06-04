// styles.go centralizes the Lipgloss theme. A renderer is bound to the actual
// output writer, so when output is piped (not a TTY) Lipgloss auto-detects an
// ASCII profile and emits no color codes — keeping scripted output clean while
// interactive terminals get the full treatment.
package cli

import (
	"io"

	"github.com/charmbracelet/lipgloss"
)

// accent is splitshot blue, with an adaptive variant for light/dark terminals.
var accentColor = lipgloss.AdaptiveColor{Light: "#2563EB", Dark: "#7AA2F7"}

// theme bundles the styles used across commands.
type theme struct {
	title   lipgloss.Style
	tagline lipgloss.Style
	heading lipgloss.Style
	label   lipgloss.Style
	share   lipgloss.Style
	secret  lipgloss.Style
	success lipgloss.Style
	warning lipgloss.Style
}

// newTheme builds a theme whose color output matches the capabilities of w.
func newTheme(w io.Writer) theme {
	r := lipgloss.NewRenderer(w)
	return theme{
		title:   r.NewStyle().Bold(true).Foreground(accentColor),
		tagline: r.NewStyle().Italic(true).Faint(true),
		heading: r.NewStyle().Bold(true).Foreground(accentColor),
		label:   r.NewStyle().Bold(true),
		share:   r.NewStyle().Foreground(accentColor),
		secret:  r.NewStyle().Bold(true).Foreground(lipgloss.Color("#16A34A")),
		success: r.NewStyle().Foreground(lipgloss.Color("#16A34A")),
		warning: r.NewStyle().Bold(true).Foreground(lipgloss.Color("#D97706")),
	}
}
