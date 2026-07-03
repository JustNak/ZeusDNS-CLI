//go:build windows
// +build windows

package cmd

import (
	"bufio"
	"fmt"
	"os"

	"github.com/JustNak/ZeusDNS-CLI/config"
	"github.com/JustNak/ZeusDNS-CLI/internal"
	"github.com/JustNak/ZeusDNS-CLI/service"
	"github.com/JustNak/ZeusDNS-CLI/tui"
)

// Wizard runs the first-run setup: a huh form that collects and live-validates
// the primary (and optional fallback) resolver, then writes the config,
// installs and starts the service.
func Wizard(configPath string, verbose bool) int {
	res, err := tui.RunWizard()
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup cancelled:", err)
		return internal.ExitMisconfig
	}
	if !res.Install {
		fmt.Println("Not installing. Run `zeusdns` again whenever you're ready.")
		return internal.ExitSuccess
	}

	cfg := config.Default()
	cfg.Upstreams = []string{res.Primary}
	if res.Fallback != "" {
		cfg.Upstreams = append(cfg.Upstreams, res.Fallback)
	}

	fmt.Println("\nConfiguring...")
	step("writing config", func() error { return cfg.Save(configPath) })

	step("installing service", func() error {
		if err := Preflight(cfg.Addr()); err != nil {
			return err
		}
		binPath, err := serviceBinPath(configPath)
		if err != nil {
			return err
		}
		_ = service.Uninstall() // idempotent reinstall
		return service.Install(binPath)
	})
	step("starting service", func() error { return service.Start() })

	fmt.Println("\n" + tui.OKStyle.Render("Done!!!"))
	fmt.Print("Enter To Exit: ")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	return internal.ExitSuccess
}

// step prints a labelled check/cross line and returns whether it succeeded.
func step(label string, fn func() error) {
	if err := fn(); err != nil {
		fmt.Printf("  %s %s  (%v)\n", tui.ErrStyle.Render("✗"), label, err)
	} else {
		fmt.Printf("  %s %s\n", tui.OKStyle.Render("✓"), label)
	}
}
