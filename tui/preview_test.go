package tui

import (
	"fmt"
	"os"
	"testing"
)

// TestPreviewRender prints the real configure-screen View() output so the
// layout can be verified without a TTY. lipgloss drops ANSI color when stdout
// is not a terminal, so the captured output shows structure rather than color.
func TestPreviewRender(t *testing.T) {
	m := initialConfigureModel([]string{
		"https://dns.controld.com/p2",
		"tls://dns.adguard.com",
		"https://doh.pub/dns-query",
	})
	m.cursor = 1
	m.results = map[int]testResult{
		0: {ok: true},
		1: {ok: false, err: "i/o timeout"},
	}
	m.pendingTest = 0

	fmt.Println("===== LIST MODE =====")
	fmt.Print(Banner() + "\n\n")
	fmt.Print(m.View())

	// add-mode view
	m2 := initialConfigureModel([]string{"https://dns.controld.com/p2"})
	m2.mode = modeAdd
	m2.addInput.SetValue("tls://dns.adguard.com")
	m2.addInput.Focus()
	fmt.Println("\n\n===== ADD MODE =====")
	fmt.Print(m2.View())

	// validating state
	m3 := initialConfigureModel([]string{"https://dns.controld.com/p2"})
	m3.mode = modeValidating
	fmt.Println("\n\n===== VALIDATING MODE =====")
	fmt.Print(m3.View())

	// sentinel so the run is obvious in -v output
	fmt.Fprintln(os.Stderr, "preview rendered")
}
