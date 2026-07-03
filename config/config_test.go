package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultIsUsable(t *testing.T) {
	c := Default()
	if c.Listener.Port != 53 {
		t.Fatalf("default port = %d, want 53", c.Listener.Port)
	}
	if !c.Windows.SetSystemDNS || !c.Windows.WFPLoopbackProtect {
		t.Fatal("Windows toggles should default on")
	}
	if err := c.Validate(); err == nil {
		t.Fatal("default has no upstreams, Validate should fail")
	}
}

func TestLoadFileOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, "upstreams:\n  - https://dns.controld.com/p2\n  - tls://dns.adguard.com\nlistener:\n  ip: 127.0.0.1\n  port: 5353\ncache:\n  size: 512\n")

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Upstreams) != 2 {
		t.Fatalf("upstreams = %v, want 2", c.Upstreams)
	}
	if c.Listener.Port != 5353 {
		t.Fatalf("port = %d, want 5353", c.Listener.Port)
	}
	if c.Cache.Size != 512 {
		t.Fatalf("cache size = %d, want 512", c.Cache.Size)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, "upstreams:\n  - https://from-file.example/dns-query\nlistener:\n  port: 5353\n")

	t.Setenv("ZEUSDNS_UPSTREAMS", "https://from-env.example/dns-query,tls://env-doT.example")
	t.Setenv("ZEUSDNS_LISTENER_PORT", "53")
	t.Setenv("ZEUSDNS_WINDOWS_WFP_LOOPBACK_PROTECT", "false")

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Upstreams) != 2 || c.Upstreams[0] != "https://from-env.example/dns-query" {
		t.Fatalf("env did not override upstreams: %v", c.Upstreams)
	}
	if c.Listener.Port != 53 {
		t.Fatalf("env did not override port: %d", c.Listener.Port)
	}
	if c.Windows.WFPLoopbackProtect {
		t.Fatal("env should have disabled WFP")
	}
}

func TestSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "config.yaml")
	c := Default()
	c.Upstreams = []string{"https://dns.controld.com/p2", "tls://dns.adguard.com"}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Upstreams) != 2 {
		t.Fatalf("round-trip upstreams = %v", loaded.Upstreams)
	}
	if err := loaded.Validate(); err != nil {
		t.Fatalf("round-trip config invalid: %v", err)
	}
}

func TestMissingFileIsNotError(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(c.Upstreams) != 0 {
		t.Fatalf("missing file should yield zero upstreams, got %v", c.Upstreams)
	}
}
