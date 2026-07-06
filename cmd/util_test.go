//go:build windows
// +build windows

package cmd

import (
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/JustNak/ZeusDNS-CLI/config"
)

func TestPreflightFreePort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	if err := Preflight(addr); err != nil {
		t.Fatalf("preflight on free port %s should pass, got: %v", addr, err)
	}
}

func TestPreflightHeldPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr().String()
	err = Preflight(addr)
	if err == nil {
		t.Fatal("preflight on a held TCP port should fail")
	}
	if !strings.Contains(err.Error(), "ctrld") {
		t.Fatalf("error should name ctrld as the likely culprit, got: %v", err)
	}
}

func TestIsAddrInUseDistinguishesErrno(t *testing.T) {
	// 10048 = WSAEADDRINUSE (genuinely held) -> must be detected.
	if !isAddrInUse(syscall.Errno(10048)) {
		t.Error("WSAEADDRINUSE should be reported as in-use")
	}
	// 10013 = WSAEACCES (access forbidden / excluded range) -> must NOT be
	// treated as in-use, or port 53 installs false-positive on non-admin runs.
	if isAddrInUse(syscall.Errno(10013)) {
		t.Error("WSAEACCES should NOT be reported as in-use")
	}
}

func TestServiceBinPath(t *testing.T) {
	// The registered binPath is ALWAYS the canonical install path — never
	// os.Executable() — so the service survives the user's build/Downloads
	// folder being moved or deleted, and self-update swaps the right file.
	exe, args, err := serviceBinPath(config.DefaultFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := config.InstallPath(); exe != want {
		t.Errorf("exe path = %q, want install path %q", exe, want)
	}
	if len(args) != 0 {
		t.Errorf("default config must not add -c args, got: %v", args)
	}

	// empty configPath -> same as default (no -c)
	if exe2, _, _ := serviceBinPath(""); exe2 != config.InstallPath() {
		t.Errorf("empty configPath exe = %q, want %q", exe2, config.InstallPath())
	}

	// custom config -> install-path exe + ["-c", path]
	exeC, argsCustom, err := serviceBinPath(`C:\custom\config.yaml`)
	if err != nil {
		t.Fatal(err)
	}
	if exeC != config.InstallPath() {
		t.Errorf("custom config exe = %q, want %q", exeC, config.InstallPath())
	}
	if len(argsCustom) != 2 || argsCustom[0] != "-c" || argsCustom[1] != `C:\custom\config.yaml` {
		t.Errorf("custom config should return [-c path], got: %v", argsCustom)
	}
}
