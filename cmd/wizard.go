//go:build windows
// +build windows

package cmd

import (
	"fmt"
	"os"

	"github.com/JustNak/ZeusDNS-CLI/config"
	"github.com/JustNak/ZeusDNS-CLI/internal"
	"github.com/JustNak/ZeusDNS-CLI/service"
	"github.com/JustNak/ZeusDNS-CLI/tui"
	"github.com/JustNak/ZeusDNS-CLI/windows"
)

// Wizard runs the first-run setup: a huh form that collects and live-validates
// the primary (and optional fallback) resolver, then writes the config,
// installs and starts the service.
//
// A non-admin user can still collect and save a config (resolver validation
// needs no admin); the install step is skipped with a clear message so the
// user can re-run `zeusdns` elevated to finish setup via the resume path.
func Wizard(configPath string, verbose bool) int {
	res, err := tui.RunWizard()
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup cancelled:", err)
		return internal.ExitCancelled
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
	if err := step("writing config", func() error { return cfg.Save(configPath) }); err != nil {
		return internal.ExitMisconfig
	}

	// Installing/starting the service needs admin. If we're not elevated,
	// stop here with a clear message — the config is saved, so re-running
	// `zeusdns` as admin will resume setup and install the service.
	if !requireAdmin("install the ZeusDNS service") {
		fmt.Println("\n" + tui.OKStyle.Render("Config saved."))
		fmt.Println("To install the service, re-open this terminal as administrator and run `zeusdns`.")
		Pause()
		return internal.ExitSuccess
	}

	if err := step("installing service", func() error {
		_, err := installService(configPath)
		if err != nil {
			return err
		}
		// Add installation directory to PATH so `zeusdns` resolves from
		// any terminal (new processes only). Non-fatal: the service works
		// without it.
		if err := windows.AddToMachinePath(config.InstallDir); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ add to PATH: %v\n", err)
		}
		return nil
	}); err != nil {
		return internal.ExitService
	}
	if err := step("starting service", func() error { return service.Start() }); err != nil {
		return internal.ExitService
	}

	fmt.Println("\n" + tui.OKStyle.Render("Done!!!"))
	Pause()
	return internal.ExitSuccess
}

// step prints a labelled check/cross line and returns the first error.
func step(label string, fn func() error) error {
	if err := fn(); err != nil {
		fmt.Printf("  %s %s  (%v)\n", tui.ErrStyle.Render("✗"), label, err)
		return err
	}
	fmt.Printf("  %s %s\n", tui.OKStyle.Render("✓"), label)
	return nil
}
