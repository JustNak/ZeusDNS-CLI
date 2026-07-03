// ZeusDNS-CLI — a stripped-down Windows-only secure DNS forwarder.
//
// It runs a local DNS server on 127.0.0.1:53 that forwards to an ordered list
// of DoH/DoT upstreams, sets 127.0.0.1 as the system DNS while running, and
// installs a WFP filter so VPN "block outside DNS" rules don't kill it.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/JustNak/ZeusDNS-CLI/cmd"
	"github.com/JustNak/ZeusDNS-CLI/config"
	"github.com/JustNak/ZeusDNS-CLI/internal"
	"github.com/JustNak/ZeusDNS-CLI/service"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		verbose     bool
		configPath  string
		showVersion bool
	)
	fs := flag.NewFlagSet("zeusdns", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.BoolVar(&verbose, "v", false, "verbose output")
	fs.StringVar(&configPath, "c", "", "config file `path`")
	fs.StringVar(&configPath, "config", "", "config file `path`")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.Usage = func() { printUsage() }

	if err := fs.Parse(os.Args[1:]); err != nil {
		return internal.ExitBadArg
	}
	if showVersion {
		fmt.Println("zeusdns", cmd.Version)
		return internal.ExitSuccess
	}

	// When launched by the Service Control Manager, run the server loop.
	if service.IsWindowsService() {
		err := service.Run(config.ServiceName, func(ctx context.Context) error {
			return cmd.Run(ctx, configPath, verbose)
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "service error:", err)
			return internal.ExitMisconfig
		}
		return internal.ExitSuccess
	}

	args := fs.Args()
	name := ""
	if len(args) > 0 {
		name = args[0]
	}

	switch name {
	case "":
		if config.Exists(configPath) {
			return cmd.Status(configPath, verbose)
		}
		return cmd.Wizard(configPath, verbose)
	case "wizard", "setup":
		return cmd.Wizard(configPath, verbose)
	case "configure":
		return cmd.Configure(configPath, verbose)
	case "install":
		return cmd.Install(configPath, verbose)
	case "uninstall":
		return cmd.Uninstall(configPath, verbose)
	case "start":
		return cmd.Start()
	case "stop":
		return cmd.Stop()
	case "restart":
		return cmd.Restart()
	case "status":
		return cmd.Status(configPath, verbose)
	case "run":
		return cmd.RunForeground(configPath, verbose)
	case "update":
		return cmd.Update(cmd.Version, verbose)
	case "help", "-h", "--help":
		printUsage()
		return internal.ExitSuccess
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", name)
		printUsage()
		return internal.ExitBadArg
	}
}

func printUsage() {
	fmt.Printf(`zeusdns %s — Windows secure DNS forwarder

Usage:
  zeusdns                       first-run setup (or status if already configured)
  zeusdns configure             manage upstream resolvers (interactive TUI)
  zeusdns install               install & start the Windows service
  zeusdns uninstall             stop, restore system DNS, remove the service
  zeusdns start                 start the service
  zeusdns stop                  stop the service (restores system DNS)
  zeusdns restart               restart the service (re-reads config)
  zeusdns status                show service + config status
  zeusdns run                   run the server in the foreground (Ctrl+C to stop)
  zeusdns update                self-update from GitHub releases
  zeusdns --version             print version
  zeusdns -h                    this help

Flags:
  -c, --config <path>   config file (default %s)
  -v                    verbose output (also enables per-query logging)

Resolver formats: https://host/path (DoH)  or  tls://host[:853] (DoT)
Config directory:  %s
`, cmd.Version, config.DefaultFile, config.DefaultDir)
}
