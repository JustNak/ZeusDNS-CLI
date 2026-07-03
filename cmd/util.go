//go:build windows
// +build windows

package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/JustNak/ZeusDNS-CLI/config"
	"github.com/JustNak/ZeusDNS-CLI/windows"
)

// Pause prints "Press Enter to exit: " and blocks for a newline, so a
// double-clicked zeusdns.exe console window doesn't vanish before the user can
// read the output. Called only on interactive (no-arg) code paths.
func Pause() {
	fmt.Print("\nPress Enter to exit: ")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

// isAddrInUse reports whether err is a "port already in use" bind failure.
// On Windows this is WSAEADDRINUSE (10048) — i.e. another socket is genuinely
// holding the port. It deliberately does NOT treat WSAEACCES (10013, "access
// forbidden", e.g. a Windows excluded port range or a non-admin bind of port
// 53) as "in use": the service runs as LocalSystem and may bind fine there.
func isAddrInUse(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.Errno(10048) // WSAEADDRINUSE — port genuinely held
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "in use") || strings.Contains(s, "address already in use")
}

// IsElevated reports whether the current process is running with admin rights.
// Exposed so main.go can decide whether to resume-setup without attempting a
// privileged call that would throw a raw SCM error.
func IsElevated() bool { return windows.IsElevated() }

// requireAdmin returns true if the current process is elevated. If not, it
// prints a clear, actionable message naming the action that needs admin and
// returns false — callers should then return ExitMisconfig without attempting
// the privileged operation (so the user never sees a raw SCM "Access denied").
func requireAdmin(action string) bool {
	if windows.IsElevated() {
		return true
	}
	fmt.Fprintf(os.Stderr, "Administrator rights are required to %s.\n\n", action)
	fmt.Fprintln(os.Stderr, "Re-open your terminal as administrator, then run `zeusdns` again:")
	fmt.Fprintln(os.Stderr, "  Right-click Windows Terminal / PowerShell / Command Prompt")
	fmt.Fprintln(os.Stderr, "  → \"Run as administrator\"")
	return false
}

// serviceBinPath returns the absolute executable path and the extra args
// to pass to CreateService. CreateService builds the registered binPath as
// EscapeArg(exe) + " " + EscapeArg(arg)... so the exe must be passed
// separately from flags (passing `"exe" -c "cfg"` as one string gets
// mangled into a single quoted blob and the SCM can't find the file).
//
// A -c flag is appended only when configPath is a non-default file; without
// it, `zeusdns install -c custom.yaml` would preflight custom's port but the
// service would run against the default config (port 53).
func serviceBinPath(configPath string) (exe string, args []string, err error) {
	exe, err = os.Executable()
	if err != nil {
		return "", nil, err
	}
	exe, _ = filepath.Abs(exe)
	if configPath != "" && configPath != config.DefaultFile {
		args = []string{"-c", configPath}
	}
	return exe, args, nil
}

// Preflight checks that the local DNS port is free before the service binds it.
// If something already holds it — ctrld, AdGuard Home, or another DNS server on
// 127.0.0.1:53 — it returns a human-readable error naming the likely culprit,
// instead of letting the service install and crash-loop on bind.
//
// Access-denied errors (Windows excluded port ranges) are ignored: the CLI
// process may lack the rights to bind port 53 even though the service (running
// as LocalSystem) can.
func Preflight(addr string) error {
	if pc, err := net.ListenPacket("udp", addr); err == nil {
		_ = pc.Close()
	} else if isAddrInUse(err) {
		return fmt.Errorf("UDP %s already in use — is ctrld or another DNS server running? Stop it first", addr)
	}
	if l, err := net.Listen("tcp", addr); err == nil {
		_ = l.Close()
	} else if isAddrInUse(err) {
		return fmt.Errorf("TCP %s already in use — is ctrld or another DNS server running? Stop it first", addr)
	}
	return nil
}
