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

// rollbackInstall cleans up artifacts from a failed install after
// promoteBinary succeeded. It removes the installed binary, the install
// directory (best-effort), and the PATH entry so a partial install doesn't
// leave a ghost behind.
func rollbackInstall(exe string) {
	_ = os.Remove(config.InstallPath())
	_ = os.Remove(config.InstallDir) // best-effort; may be non-empty → ignore
	_ = windows.RemoveFromMachinePath(config.InstallDir)
}

// Install (re)installs and starts the service using the existing config.
func Install(configPath string, verbose bool) int {
	if !requireAdmin("install the ZeusDNS service") {
		return internal.ExitService
	}
	if !config.Exists(configPath) {
		fmt.Fprintln(os.Stderr, "no config found. run `zeusdns` first to set up.")
		return internal.ExitMisconfig
	}
	// If our own service is running, stop it first so it releases port 53.
	if st, _ := service.Status(); st == "running" || st == "start-pending" {
		_ = service.Stop()
	}
	_ = service.Uninstall() // idempotent: clear any leftover registration

	exe, err := installService(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return internal.ExitService
	}
	fmt.Println(tui.OKStyle.Render("service installed"))
	// Put the install dir on the machine PATH so `zeusdns` resolves from any
	// terminal (new processes only — the current shell keeps its old env
	// block until the user opens a fresh one). Non-fatal: the service works
	// without it; we just print a hint.
	if err := windows.AddToMachinePath(config.InstallDir); err != nil {
		fmt.Fprintln(os.Stderr, "add to PATH (service still installed):", err)
	} else {
		fmt.Println(tui.OKStyle.Render("added to PATH"))
	}
	if err := service.Start(); err != nil {
		rollbackInstall(exe)
		fmt.Fprintln(os.Stderr, "start:", err)
		return internal.ExitService
	}
	fmt.Println(tui.OKStyle.Render("service started"))
	fmt.Println("open a new terminal to use `zeusdns` from anywhere.")
	return internal.ExitSuccess
}

// Uninstall stops the service, restores the system DNS, removes the service,
// deletes the promoted binary + install dir, and drops the PATH entry.
func Uninstall(configPath string, verbose bool) int {
	if !requireAdmin("uninstall the ZeusDNS service") {
		return internal.ExitService
	}
	_ = service.Stop()
	_ = windows.RestoreSystemDNS() // belt-and-suspenders if the stop handler missed it
	if err := service.Uninstall(); err != nil {
		fmt.Fprintln(os.Stderr, "uninstall:", err)
		return internal.ExitService
	}
	// Remove the promoted binary. The install dir is removed best-effort — a
	// lingering .old file (pending reboot-delete from a prior self-update) or
	// user files would leave it non-empty, which is fine and harmless.
	if err := os.Remove(config.InstallPath()); err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "remove install binary:", err)
	}
	_ = os.Remove(config.InstallDir)
	if err := windows.RemoveFromMachinePath(config.InstallDir); err != nil {
		fmt.Fprintln(os.Stderr, "remove from PATH:", err)
	}
	fmt.Println(tui.OKStyle.Render("service uninstalled; system DNS restored"))
	return internal.ExitSuccess
}

// Start starts the installed service.
func Start() int {
	if err := service.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return internal.ExitService
	}
	fmt.Println(tui.OKStyle.Render("service started"))
	return internal.ExitSuccess
}

// Stop stops the running service (its stop handler restores the system DNS).
func Stop() int {
	if err := service.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, "stop:", err)
		return internal.ExitService
	}
	fmt.Println(tui.OKStyle.Render("service stopped (system DNS restored)"))
	return internal.ExitSuccess
}

// Restart restarts the service, re-reading the config.
func Restart() int {
	if err := service.Restart(); err != nil {
		fmt.Fprintln(os.Stderr, "restart:", err)
		return internal.ExitService
	}
	fmt.Println(tui.OKStyle.Render("service restarted"))
	return internal.ExitSuccess
}

// Update checks GitHub for a newer release and swaps the installed binary
// (config.InstallPath) if found, restarting the service around the swap if it
// was running. Runs against the install dir, NOT the running exe, so it works
// the same whether launched from the install path or a dev build — but it
// refuses if no installed binary exists (run `zeusdns install` first).
func Update(version string, verbose bool) int {
	if !requireAdmin("update ZeusDNS") {
		return internal.ExitService
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	msg, err := updater.Update(ctx, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "update:", err)
		return internal.ExitFailure
	}
	fmt.Println(tui.OKStyle.Render(msg))
	return internal.ExitSuccess
}
