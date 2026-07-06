//go:build windows
// +build windows

package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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

// serviceBinPath returns the canonical install path of the binary plus the
// extra args to pass to CreateService. The registered binPath is ALWAYS
// config.InstallPath() — never os.Executable() — so the service keeps running
// after the user deletes their build/Downloads folder. Install is responsible
// for promoting the binary there first (see promoteBinary).
//
// CreateService builds the registered binPath as
// EscapeArg(exe) + " " + EscapeArg(arg)... so the exe must be passed
// separately from flags (passing `"exe" -c "cfg"` as one string gets
// mangled into a single quoted blob and the SCM can't find the file).
//
// A -c flag is appended only when configPath is a non-default file; without
// it, `zeusdns install -c custom.yaml` would preflight custom's port but the
// service would run against the default config (port 53).
func serviceBinPath(configPath string) (exe string, args []string, err error) {
	exe = config.InstallPath()
	if configPath != "" && configPath != config.DefaultFile {
		args = []string{"-c", configPath}
	}
	return exe, args, nil
}

// promoteBinary copies the running executable to the canonical install
// location (config.InstallPath) so the registered service points at a stable
// path that doesn't move when the user deletes their build or Downloads
// folder. Idempotent: copying onto itself is a no-op. The install directory is
// created if missing. Requires admin (writing under %ProgramFiles%).
func promoteBinary() (string, error) {
	src, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate running binary: %w", err)
	}
	src, _ = filepath.Abs(src)
	dst := config.InstallPath()
	if samePath(src, dst) {
		return dst, nil // already running from the install location
	}
	if err := os.MkdirAll(config.InstallDir, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w (need admin?)", config.InstallDir, err)
	}
	if err := copyFile(src, dst); err != nil {
		return "", fmt.Errorf("copy binary to %s: %w", dst, err)
	}
	return dst, nil
}

// copyFile copies src to dst, truncating dst if it exists. Mode is taken from
// src so the installed binary keeps the build's permissions.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// samePath reports whether two paths are the same file, case-insensitively
// (Windows filesystems are case-insensitive). Used by promoteBinary to skip
// the copy when the binary is already running from the install location.
func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// Preflight checks that the local DNS port is free before the service binds it.
// If something already holds it — ctrld, AdGuard Home, or another DNS server on
// 127.0.0.1:53 — it returns a human-readable error naming the likely culprit,
// instead of letting the service install and crash-loop on bind.
//
// A retry loop (up to 6 tries × 300 ms backoff) is used when the bind fails
// with "address already in use". This gives the OS time to release a socket
// left by a just-stopped ZeusDNS service during self-restart/reinstall — the
// socket may linger briefly in TIME_WAIT or cleanup lag before the port is
// genuinely free. Non-address-in-use errors (access denied, bad address, etc.)
// fail fast on the first attempt.
//
// Access-denied errors (Windows excluded port ranges) are ignored: the CLI
// process may lack the rights to bind port 53 even though the service (running
// as LocalSystem) can.
func Preflight(addr string) error {
	const maxRetries = 6
	const retryDelay = 300 * time.Millisecond

	// UDP probe with retry-on-EADDRINUSE
	for i := 0; i < maxRetries; i++ {
		pc, err := net.ListenPacket("udp", addr)
		if err == nil {
			_ = pc.Close()
			break // port free, continue to TCP
		}
		if !isAddrInUse(err) {
			return err // fail fast on permission-denied, bad addr, etc.
		}
		if i == maxRetries-1 {
			return fmt.Errorf("UDP %s already in use — is ctrld or another DNS server running? Stop it first", addr)
		}
		time.Sleep(retryDelay)
	}

	// TCP probe with retry-on-EADDRINUSE
	for i := 0; i < maxRetries; i++ {
		l, err := net.Listen("tcp", addr)
		if err == nil {
			_ = l.Close()
			return nil
		}
		if !isAddrInUse(err) {
			return err
		}
		if i == maxRetries-1 {
			return fmt.Errorf("TCP %s already in use — is ctrld or another DNS server running? Stop it first", addr)
		}
		time.Sleep(retryDelay)
	}
	return nil
}
