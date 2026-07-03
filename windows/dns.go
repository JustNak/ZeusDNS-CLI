//go:build windows
// +build windows

// Package windows contains Windows-only native helpers: setting/restoring
// the system DNS servers and the WFP loopback-DNS protection filter.
package windows

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/JustNak/ZeusDNS-CLI/config"
)

// ifaceDNS is the subset of Get-DnsClientServerAddress output we persist.
type ifaceDNS struct {
	InterfaceAlias  string   `json:"InterfaceAlias"`
	ServerAddresses []string `json:"ServerAddresses"`
}

// ps runs a PowerShell command and returns its combined output.
func ps(script string) ([]byte, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	return cmd.CombinedOutput()
}

// quoteAlias wraps an interface alias in single quotes for PowerShell,
// escaping any embedded single quote. Interface aliases rarely contain one,
// but guard against injection regardless.
func quoteAlias(alias string) string {
	return "'" + strings.ReplaceAll(alias, "'", "''") + "'"
}

// getSystemDNS reads the current IPv4 DNS server addresses per interface.
func getSystemDNS() ([]ifaceDNS, error) {
	script := `Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress -Depth 3`
	out, err := ps(script)
	if err != nil {
		return nil, fmt.Errorf("Get-DnsClientServerAddress: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return normalizePSJSON(out)
}

// SaveSystemDNS records the current IPv4 DNS server addresses per interface
// to config.PrevDNSFile so they can be restored on stop/uninstall.
func SaveSystemDNS() error {
	entries, err := getSystemDNS()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.DefaultDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(config.PrevDNSFile, data, 0o644)
}

// GetBootstrapDNS returns the current system DNS server IPs suitable for use
// as a bootstrap resolver — the servers ZeusDNS will query directly to
// resolve DoH/DoT upstream hostnames, bypassing the system resolver (which
// becomes 127.0.0.1 = ZeusDNS itself after takeover and would loop). Loopback
// and unspecified addresses are excluded. If none remain usable, well-known
// public resolvers are returned as a fallback.
//
// Must be called BEFORE SetSystemDNS so it captures the real upstream DNS
// (the router or VPN's DNS), not 127.0.0.1.
func GetBootstrapDNS() []string {
	entries, err := getSystemDNS()
	if err != nil {
		return publicBootstrap
	}
	seen := map[string]bool{}
	var ips []string
	for _, e := range entries {
		for _, s := range e.ServerAddresses {
			ip := net.ParseIP(s)
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			if seen[s] {
				continue
			}
			seen[s] = true
			ips = append(ips, s)
		}
	}
	if len(ips) == 0 {
		return publicBootstrap
	}
	return ips
}

// publicBootstrap is the fallback when no usable system DNS is available
// (e.g. the only server was 127.0.0.1 from another forwarder already running).
var publicBootstrap = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}

// normalizePSJSON handles PowerShell's habit of emitting a bare object (not
// an array) when only one interface is returned.
func normalizePSJSON(b []byte) ([]ifaceDNS, error) {
	var single ifaceDNS
	if err := json.Unmarshal(b, &single); err == nil && single.InterfaceAlias != "" {
		return []ifaceDNS{single}, nil
	}
	var arr []ifaceDNS
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, fmt.Errorf("parse dns json: %w", err)
	}
	return arr, nil
}

func loadPrev() ([]ifaceDNS, error) {
	data, err := os.ReadFile(config.PrevDNSFile)
	if err != nil {
		return nil, err
	}
	var arr []ifaceDNS
	if err := json.Unmarshal(data, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

// SetSystemDNS points every interface that previously had a DNS server at addr
// (normally 127.0.0.1). Requires elevation.
func SetSystemDNS(addr string) error {
	entries, err := loadPrev()
	if err != nil {
		return fmt.Errorf("load prev dns: %w", err)
	}
	for _, e := range entries {
		if len(e.ServerAddresses) == 0 {
			continue
		}
		script := fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias %s -ServerAddresses '%s'`, quoteAlias(e.InterfaceAlias), addr)
		if out, err := ps(script); err != nil {
			return fmt.Errorf("set dns %s: %w: %s", e.InterfaceAlias, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// RestoreSystemDNS returns each interface to its saved DNS servers, or resets
// to DHCP for interfaces that had none. Requires elevation.
func RestoreSystemDNS() error {
	entries, err := loadPrev()
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing to restore
		}
		return err
	}
	for _, e := range entries {
		var script string
		if len(e.ServerAddresses) == 0 {
			script = fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias %s -ResetServerAddresses`, quoteAlias(e.InterfaceAlias))
		} else {
			script = fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias %s -ServerAddresses '%s'`, quoteAlias(e.InterfaceAlias), strings.Join(e.ServerAddresses, ","))
		}
		if out, err := ps(script); err != nil {
			return fmt.Errorf("restore dns %s: %w: %s", e.InterfaceAlias, err, strings.TrimSpace(string(out)))
		}
	}
	_ = os.Remove(config.PrevDNSFile)
	return nil
}
