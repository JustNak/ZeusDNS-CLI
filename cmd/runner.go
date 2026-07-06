//go:build windows
// +build windows

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/JustNak/ZeusDNS-CLI/config"
	"github.com/JustNak/ZeusDNS-CLI/dns"
	"github.com/JustNak/ZeusDNS-CLI/internal"
	"github.com/JustNak/ZeusDNS-CLI/windows"
)

// Run is the DNS server entry point shared by the service handler and the
// foreground `run` command. It performs system-DNS and WFP setup, starts the
// local server, and on context cancellation reverses the setup.
func Run(ctx context.Context, configPath string, verbose bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if verbose {
		cfg.Log.Level = "verbose"
	}

	log, err := internal.NewLogger(cfg.Log.Level, cfg.Log.Path, verbose)
	if err != nil {
		return err
	}
	defer log.Close()

	log.Info("zeusdns starting", "version", Version, "addr", cfg.Addr())

	// Capture the system's current DNS servers (router or VPN DNS) BEFORE
	// setting 127.0.0.1: they become the bootstrap resolver used to resolve
	// DoH/DoT upstream hostnames directly, bypassing the system resolver
	// (which is about to point at 127.0.0.1 = ZeusDNS itself and would loop).
	// See NewBootstrapResolver / GetBootstrapDNS.
	var bootstrap []string
	if cfg.Windows.SetSystemDNS {
		bootstrap = windows.GetBootstrapDNS()
		log.Info("bootstrap resolver", "servers", bootstrap)
		if err := windows.SaveSystemDNS(); err != nil {
			log.Warn("save system dns failed (need admin?)", "err", err)
		}
		if err := windows.SetSystemDNS("127.0.0.1"); err != nil {
			log.Warn("set system dns failed (need admin?)", "err", err)
		} else {
			log.Info("system dns set to 127.0.0.1")
		}
	}

	var wfp *windows.LoopbackProtector
	if cfg.Windows.WFPLoopbackProtect {
		wfp = windows.NewLoopbackProtector()
		if err := wfp.Enable(); err != nil {
			log.Warn("wfp loopback protect failed (need admin?)", "err", err)
		} else {
			log.Info("wfp loopback protect enabled")
		}
	}

	srv, err := dns.NewServer(cfg, log, dns.NewBootstrapResolver(bootstrap))
	if err != nil {
		cleanup(log, cfg, wfp)
		return err
	}

	// srv.Start blocks until ctx is canceled (service stop or Ctrl+C).
	startErr := srv.Start(ctx)
	if startErr != nil {
		log.Error("dns server exited", "err", startErr)
	}
	log.Info("zeusdns stopping")
	cleanup(log, cfg, wfp)
	if startErr != nil {
		return fmt.Errorf("dns server: %w", startErr)
	}
	return nil
}

func cleanup(log *internal.Logger, cfg *config.Config, wfp *windows.LoopbackProtector) {
	if wfp != nil {
		if err := wfp.Disable(); err != nil {
			log.Warn("wfp disable failed", "err", err)
		}
	}
	if cfg.Windows.SetSystemDNS {
		if err := windows.RestoreSystemDNS(); err != nil {
			log.Warn("restore system dns failed", "err", err)
		} else {
			log.Info("system dns restored")
		}
	}
}

// RunForeground runs the server in the current terminal until Ctrl+C.
func RunForeground(configPath string, verbose bool) int {
	if !config.Exists(configPath) {
		fmt.Fprintln(os.Stderr, "no config found. run `zeusdns` first to set up.")
		return internal.ExitMisconfig
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := Run(ctx, configPath, verbose); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return internal.ExitMisconfig
	}
	return internal.ExitSuccess
}
