// Package config loads, layers, validates, and saves the ZeusDNS YAML config.
//
// Layering (lowest to highest precedence):
//
//	Defaults  <  file (C:\ProgramData\ZeusDNS\config.yaml)  <  env (ZEUSDNS_*)  <  CLI flags
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Well-known paths on Windows.
const (
	DefaultDir  = `C:\ProgramData\ZeusDNS`
	DefaultFile = `C:\ProgramData\ZeusDNS\config.yaml`
	PrevDNSFile = `C:\ProgramData\ZeusDNS\prev_dns.json`
	ServiceName = "ZeusDNS"
	ServiceDesc = "ZeusDNS-CLI - local secure DNS forwarder"
	InstallDir  = `C:\Program Files\ZeusDNS`
	BinaryName  = "zeusdns.exe"
)

// Config is the full on-disk configuration.
type Config struct {
	Upstreams []string `yaml:"upstreams"`
	Listener  Listener `yaml:"listener"`
	Cache     Cache    `yaml:"cache"`
	Log       Log      `yaml:"log"`
	Windows   Windows  `yaml:"windows"`
}

// Listener is the local address the DNS server binds.
type Listener struct {
	IP   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

// Cache sizes the in-process LRU+TTL cache (0 disables it).
type Cache struct {
	Size int `yaml:"size"`
}

// Log controls log level and file path.
type Log struct {
	Level string `yaml:"level"`
	Path  string `yaml:"path"`
}

// Windows holds Windows-specific behaviour toggles.
type Windows struct {
	SetSystemDNS       bool `yaml:"set_system_dns"`
	WFPLoopbackProtect bool `yaml:"wfp_loopback_protect"`
}

// Default returns a config with sensible Windows defaults.
func Default() *Config {
	return &Config{
		Upstreams: []string{},
		Listener:  Listener{IP: "127.0.0.1", Port: 53},
		Cache:     Cache{Size: 1024},
		Log:       Log{Level: "info", Path: filepath.Join(DefaultDir, "zeusdns.log")},
		Windows:   Windows{SetSystemDNS: true, WFPLoopbackProtect: true},
	}
}

// Exists reports whether a config file is present at path.
func Exists(path string) bool {
	if path == "" {
		path = DefaultFile
	}
	_, err := os.Stat(path)
	return err == nil
}

// Load reads the file (falling back to defaults if it is absent), then applies
// environment overrides. Missing file is not an error; a corrupt file is.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultFile
	}
	cfg := Default()

	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	applyEnv(cfg)
	return cfg, nil
}

// Save writes the config to path, creating parent directories as needed.
func (c *Config) Save(path string) error {
	if path == "" {
		path = DefaultFile
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// Validate checks the config is usable: at least one upstream and a valid port.
func (c *Config) Validate() error {
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("no upstreams configured")
	}
	if c.Listener.Port <= 0 || c.Listener.Port > 65535 {
		return fmt.Errorf("listener port %d out of range", c.Listener.Port)
	}
	if c.Listener.IP == "" {
		return fmt.Errorf("listener ip is empty")
	}
	return nil
}

// Addr returns the listener "ip:port" string.
func (c *Config) Addr() string { return fmt.Sprintf("%s:%d", c.Listener.IP, c.Listener.Port) }

// applyEnv overlays ZEUSDNS_* environment variables on top of file/defaults.
func applyEnv(c *Config) {
	if v := os.Getenv("ZEUSDNS_UPSTREAMS"); v != "" {
		c.Upstreams = splitCSV(v)
	}
	if v := os.Getenv("ZEUSDNS_LISTENER_IP"); v != "" {
		c.Listener.IP = v
	}
	if v := os.Getenv("ZEUSDNS_LISTENER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			c.Listener.Port = p
		}
	}
	if v := os.Getenv("ZEUSDNS_CACHE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Cache.Size = n
		}
	}
	if v := os.Getenv("ZEUSDNS_LOG_LEVEL"); v != "" {
		c.Log.Level = v
	}
	if v := os.Getenv("ZEUSDNS_LOG_PATH"); v != "" {
		c.Log.Path = v
	}
	if v := os.Getenv("ZEUSDNS_WINDOWS_SET_SYSTEM_DNS"); v != "" {
		c.Windows.SetSystemDNS = parseBool(v)
	}
	if v := os.Getenv("ZEUSDNS_WINDOWS_WFP_LOOPBACK_PROTECT"); v != "" {
		c.Windows.WFPLoopbackProtect = parseBool(v)
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}
