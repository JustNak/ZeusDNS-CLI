//go:build windows
// +build windows

package cmd

import (
	"github.com/JustNak/ZeusDNS-CLI/config"
	"github.com/JustNak/ZeusDNS-CLI/service"
	"github.com/JustNak/ZeusDNS-CLI/windows"
)

// installService performs the core install sequence: load and validate the
// config, preflight port availability, promote the running binary, register
// the Windows service, and add the install directory to the machine PATH.
//
// It returns the promoted binary path (needed by callers for rollback on
// Start failure) or an error. AddToMachinePath errors are non-fatal.
//
// Callers are responsible for admin elevation, stopping a running service
// before calling this, and starting the service after a successful install.
func installService(configPath string) (string, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return "", err
	}
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	if err := Preflight(cfg.Addr()); err != nil {
		return "", err
	}
	exe, err := promoteBinary()
	if err != nil {
		return "", err
	}
	binPath, args, err := serviceBinPath(configPath)
	if err != nil {
		rollbackInstall(exe)
		return exe, err
	}
	_ = service.Uninstall() // idempotent reinstall
	if err := service.Install(binPath, args...); err != nil {
		rollbackInstall(exe)
		return exe, err
	}
	_ = windows.AddToMachinePath(config.InstallDir) // non-fatal
	return exe, nil
}
