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
	// default config -> just the quoted exe, no -c flag
	bp, err := serviceBinPath(config.DefaultFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(bp, `"`) || !strings.HasSuffix(bp, `"`) {
		t.Errorf("default binPath should be just the quoted exe: %q", bp)
	}
	if strings.Contains(bp, "-c") {
		t.Errorf("default config must not add -c: %q", bp)
	}

	// empty configPath -> same as default (no -c)
	bpEmpty, _ := serviceBinPath("")
	if strings.Contains(bpEmpty, "-c") {
		t.Errorf("empty configPath must not add -c: %q", bpEmpty)
	}

	// custom config -> quoted exe + -c "path"
	bpCustom, err := serviceBinPath(`C:\custom\config.yaml`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bpCustom, `-c "C:\custom\config.yaml"`) {
		t.Errorf("custom config should append -c \"path\": %q", bpCustom)
	}
	if !strings.HasPrefix(bpCustom, `"`) {
		t.Errorf("custom binPath exe should be quoted: %q", bpCustom)
	}
}
