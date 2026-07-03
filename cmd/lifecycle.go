//go:build windows
// +build windows

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/JustNak/ZeusDNS-CLI/config"
	"github.com/JustNak/ZeusDNS-CLI/internal"
	"github.com/JustNak/ZeusDNS-CLI/service"
	"github.com/JustNak/ZeusDNS-CLI/tui"
	"github.com/JustNak/ZeusDNS-CLI/updater"
	"github.com/JustNak/ZeusDNS-CLI/windows"
)

func resolvedPath(configPath string) string {
	if configPath == "" {
		return config.DefaultFile
	}
	return configPath
}

// Status prints service state and a config summary.
func Status(configPath string, verbose bool) int {
	if st, err := service.Status(); err != nil {
		fmt.Printf("service: not installed (%v)\n", err)
	} else {
		fmt.Printf("service: %s\n", tui.OKStyle.Render(st))
	}

	if config.Exists(configPath) {
		if cfg, err := config.Load(configPath); err == nil {
			fmt.Printf("config:  %s\n", resolvedPath(configPath))
			fmt.Printf("listen:  %s\n", cfg.Addr())
			fmt.Printf("upstreams (%d):\n", len(cfg.Upstreams))
			for i, u := range cfg.Upstreams {
				badge := "primary"
				if i > 0 {
					badge = "fallback"
				}
				fmt.Printf("  %d. %s  [%s]\n", i+1, u, badge)
			}
			fmt.Printf("system dns auto-set: %v   wfp loopback protect: %v\n",
				cfg.Windows.SetSystemDNS, cfg.Windows.WFPLoopbackProtect)
		}
	} else {
		fmt.Printf("config:  none at %s (run `zeusdns` to set up)\n", resolvedPath(configPath))
	}
	return internal.ExitSuccess
}

// Install (re)installs and starts the service using the existing config.
func Install(configPath string, verbose bool) int {
	if !requireAdmin("install the ZeusDNS service") {
		return internal.ExitMisconfig
	}
	if !config.Exists(configPath) {
		fmt.Fprintln(os.Stderr, "no config found. run `zeusdns` first to set up.")
		return internal.ExitMisconfig
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		return internal.ExitMisconfig
	}
	// If our own service is running, stop it first so it releases port 53.
	if st, _ := service.Status(); st == "running" || st == "start-pending" {
		_ = service.Stop()
	}
	_ = service.Uninstall() // idempotent: clear any leftover registration

	// Pre-flight: port 53 must be free. If ctrld / AdGuard Home / the Windows
	// DNS cache still holds it, bail out with a clear message instead of
	// installing a service that will crash-loop on bind.
	if err := Preflight(cfg.Addr()); err != nil {
		fmt.Fprintln(os.Stderr, "pre-flight check failed:", err)
		return internal.ExitMisconfig
	}

	exe, args, err := serviceBinPath(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve bin path:", err)
		return internal.ExitMisconfig
	}
	if err := service.Install(exe, args...); err != nil {
		fmt.Fprintln(os.Stderr, "install:", err)
		return internal.ExitMisconfig
	}
	fmt.Println(tui.OKStyle.Render("service installed"))
	if err := service.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return internal.ExitMisconfig
	}
	fmt.Println(tui.OKStyle.Render("service started"))
	return internal.ExitSuccess
}

// Uninstall stops the service, restores the system DNS, and removes the service.
func Uninstall(configPath string, verbose bool) int {
	_ = service.Stop()
	_ = windows.RestoreSystemDNS() // belt-and-suspenders if the stop handler missed it
	if err := service.Uninstall(); err != nil {
		fmt.Fprintln(os.Stderr, "uninstall:", err)
		return internal.ExitMisconfig
	}
	fmt.Println(tui.OKStyle.Render("service uninstalled; system DNS restored"))
	return internal.ExitSuccess
}

// Start starts the installed service.
func Start() int {
	if err := service.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return internal.ExitMisconfig
	}
	fmt.Println(tui.OKStyle.Render("service started"))
	return internal.ExitSuccess
}

// Stop stops the running service (its stop handler restores the system DNS).
func Stop() int {
	if err := service.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, "stop:", err)
		return internal.ExitMisconfig
	}
	fmt.Println(tui.OKStyle.Render("service stopped (system DNS restored)"))
	return internal.ExitSuccess
}

// Restart restarts the service, re-reading the config.
func Restart() int {
	if err := service.Restart(); err != nil {
		fmt.Fprintln(os.Stderr, "restart:", err)
		return internal.ExitMisconfig
	}
	fmt.Println(tui.OKStyle.Render("service restarted"))
	return internal.ExitSuccess
}

// Update checks GitHub for a newer release and swaps the binary if found,
// restarting the service around the swap if it was running.
func Update(version string, verbose bool) int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	msg, err := updater.Update(ctx, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "update:", err)
		return internal.ExitMisconfig
	}
	fmt.Println(tui.OKStyle.Render(msg))
	return internal.ExitSuccess
}
