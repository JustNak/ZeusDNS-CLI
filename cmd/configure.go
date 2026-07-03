package cmd

import (
	"fmt"
	"os"

	"github.com/JustNak/ZeusDNS-CLI/config"
	"github.com/JustNak/ZeusDNS-CLI/internal"
	"github.com/JustNak/ZeusDNS-CLI/service"
	"github.com/JustNak/ZeusDNS-CLI/tui"
)

// Configure opens the bubbletea upstream-management menu and persists changes,
// restarting the service if it is running.
func Configure(configPath string, verbose bool) int {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		return internal.ExitMisconfig
	}

	res, err := tui.RunConfigure(cfg.Upstreams)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configure:", err)
		return internal.ExitMisconfig
	}
	if !res.Saved {
		fmt.Println("No changes saved.")
		return internal.ExitSuccess
	}

	cfg.Upstreams = res.Upstreams
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "config invalid:", err)
		return internal.ExitMisconfig
	}
	if err := cfg.Save(configPath); err != nil {
		fmt.Fprintln(os.Stderr, "save config:", err)
		return internal.ExitMisconfig
	}

	if st, _ := service.Status(); st == "running" {
		if err := service.Restart(); err != nil {
			fmt.Fprintln(os.Stderr, "restart service:", err)
		} else {
			fmt.Println(tui.OKStyle.Render("service restarted with new upstreams"))
		}
	} else {
		fmt.Println("Saved. Start the service with `zeusdns start`.")
	}
	return internal.ExitSuccess
}
