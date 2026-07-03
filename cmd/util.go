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

// serviceBinPath builds the SCM service binary path: the absolute executable
// path wrapped in double quotes (mandatory when it contains spaces, e.g.
// C:\Program Files\ZeusDNS\zeusdns.exe), followed by `-c <configPath>` when a
// non-default config file is in use. Without the -c flag, a service installed
// via `zeusdns install -c custom.yaml` would preflight custom.yaml's port but
// then run against the default config (port 53) at runtime.
func serviceBinPath(configPath string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, _ = filepath.Abs(exe)
	bin := "\"" + exe + "\""
	if configPath != "" && configPath != config.DefaultFile {
		bin += " -c \"" + configPath + "\""
	}
	return bin, nil
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
