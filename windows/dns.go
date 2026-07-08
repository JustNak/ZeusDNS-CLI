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
	Dhcp            string   `json:"Dhcp,omitempty"` // "Enabled"/"Disabled" from Get-NetIPInterface; drives restore mode
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

// parseDhcpJSON transforms the output of Get-NetIPInterface into a map of
// interface alias → DHCP state. Like normalizePSJSON it handles PowerShell's
// single-object-vs-array ambiguity.
// dhcpString normalizes a raw Dhcp value from Get-NetIPInterface output into
// the string "Enabled"/"Disabled". ConvertTo-Json emits the .NET enum as its
// underlying integer (1/0) when the value is not cast, but as the string when
// .ToString() is applied in the pipeline; accept both shapes so a future
// PowerShell change doesn't silently disable the reset-to-automatic restore.
func dhcpString(d any) string {
	switch v := d.(type) {
	case string:
		return v
	case float64: // JSON numbers decode to float64
		if v == 1 {
			return "Enabled"
		}
		return "Disabled"
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func parseDhcpJSON(b []byte) map[string]string {
	type row struct {
		InterfaceAlias string `json:"InterfaceAlias"`
		Dhcp           any    `json:"Dhcp"`
	}
	// Try single object first.
	var single row
	if err := json.Unmarshal(b, &single); err == nil && single.InterfaceAlias != "" {
		return map[string]string{single.InterfaceAlias: dhcpString(single.Dhcp)}
	}
	var arr []row
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil
	}
	m := make(map[string]string, len(arr))
	for _, r := range arr {
		m[r.InterfaceAlias] = dhcpString(r.Dhcp)
	}
	return m
}

// getSystemDNSAndDhcp runs a single PowerShell script that fetches both DNS
// server addresses and DHCP state for all IPv4 interfaces, returning the
// combined result. This replaces the previous two-launch approach (one for
// Get-DnsClientServerAddress, one for Get-NetIPInterface).
func getSystemDNSAndDhcp() ([]ifaceDNS, error) {
	script := `$dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses)
try {
  $dhcp = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop | Select-Object InterfaceAlias,@{n='Dhcp';e={$_.Dhcp.ToString()}})
} catch {
  $dhcp = $null
}
@{dns=$dns; dhcp=$dhcp} | ConvertTo-Json -Compress -Depth 5`
	out, err := ps(script)
	if err != nil {
		return nil, fmt.Errorf("getSystemDNSAndDhcp: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// Parse the combined JSON object.
	var combined struct {
		DNS  json.RawMessage `json:"dns"`
		Dhcp json.RawMessage `json:"dhcp"`
	}
	if err := json.Unmarshal(out, &combined); err != nil {
		return nil, fmt.Errorf("parse combined output: %w", err)
	}

	// Parse DNS entries.  @() forces an array in PS, so single-object
	// ambiguity is eliminated, but normalizePSJSON remains defensive.
	entries, err := normalizePSJSON([]byte(combined.DNS))
	if err != nil {
		return nil, fmt.Errorf("parse dns from combined: %w", err)
	}

	// Parse DHCP state.  When Get-NetIPInterface is unavailable (old
	// systems, constrained runtimes) the catch block sets $dhcp = $null
	// which serialises as JSON null.  Degrade gracefully — return the
	// DNS entries without DHCP annotation (same as the historic non-fatal
	// path).  An empty array [] is also handled (no interfaces match).
	if combined.Dhcp != nil && string(combined.Dhcp) != "null" {
		dhcpMap := parseDhcpJSON([]byte(combined.Dhcp))
		for i := range entries {
			if d, ok := dhcpMap[entries[i].InterfaceAlias]; ok {
				entries[i].Dhcp = d
			}
		}
	}
	return entries, nil
}

// getSystemDNS reads the current IPv4 DNS server addresses per interface and
// annotates each entry with its DHCP state so RestoreSystemDNS can distinguish
// "automatic DHCP DNS" from "manually-set static DNS".
func getSystemDNS() ([]ifaceDNS, error) {
	return getSystemDNSAndDhcp()
}

// SaveSystemDNS records the current IPv4 DNS server addresses per interface
// to config.PrevDNSFile so they can be restored on stop/uninstall.
func SaveSystemDNS() error {
	entries, err := getSystemDNS()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.DefaultDir, 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(config.PrevDNSFile, data, 0o640)
}

// GetBootstrapDNS returns the current system DNS server IPs suitable for use
// as a bootstrap resolver — the servers ZeusDNS will query directly to
// resolve DoH/DoT upstream hostnames, bypassing the system resolver (which
// becomes 127.0.0.1 = ZeusDNS itself after takeover and would loop). Loopback,
// link-local (captive-portal APIPA), multicast, and unspecified addresses are
// excluded. If none remain usable, well-known
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
			// Exclude loopback, link-local (captive-portal APIPA), multicast — none are usable resolvers.
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
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

	// Build a single PowerShell script that sets all interfaces at once.
	var lines []string
	for _, e := range entries {
		if len(e.ServerAddresses) == 0 {
			continue
		}
		alias := quoteAlias(e.InterfaceAlias)
		lines = append(lines, fmt.Sprintf(
			`try{Set-DnsClientServerAddress -InterfaceAlias %s -ServerAddresses '%s' -ErrorAction Stop}catch{$errors+=@{iface=%s;err=$_.Exception.Message}}`,
			alias, addr, alias,
		))
	}
	if len(lines) == 0 {
		return nil
	}

	script := "$errors=@();" + strings.Join(lines, ";") + ";ConvertTo-Json -Compress -InputObject $errors"
	out, err := ps(script)
	if err != nil {
		return fmt.Errorf("set dns: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// Parse error array from PS — if non-empty, report all failures.
	var errs []struct {
		Iface string `json:"iface"`
		Err   string `json:"err"`
	}
	if err := json.Unmarshal(out, &errs); err == nil && len(errs) > 0 {
		var msgs []string
		for _, e := range errs {
			msgs = append(msgs, fmt.Sprintf("%s: %s", e.Iface, e.Err))
		}
		return fmt.Errorf("set dns failed for: %s", strings.Join(msgs, "; "))
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

	// Build a single PowerShell script that restores all interfaces at once.
	var lines []string
	for _, e := range entries {
		alias := quoteAlias(e.InterfaceAlias)
		// DHCP-aware restore: interfaces whose IP config is DHCP ("Obtain DNS
		// server address automatically") should use -ResetServerAddresses to
		// return to automatic DNS, not a static rewrite.
		//
		// Blind spot: a DHCP-IP interface with a manual DNS override
		// (rare power-user setup) will be reset to automatic DNS. This is the
		// correct target state for this tool — ZeusDNS is the user's chosen
		// DNS manager and should own the DNS config.
		var cmd string
		switch {
		case e.Dhcp == "Enabled" || len(e.ServerAddresses) == 0:
			cmd = fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias %s -ResetServerAddresses`, alias)
		default:
			servers := strings.Join(e.ServerAddresses, ",")
			cmd = fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias %s -ServerAddresses '%s'`, alias, servers)
		}
		lines = append(lines, fmt.Sprintf(
			`try{%s -ErrorAction Stop}catch{$errors+=@{iface=%s;err=$_.Exception.Message}}`,
			cmd, alias,
		))
	}

	script := "$errors=@();" + strings.Join(lines, ";") + ";ConvertTo-Json -Compress -InputObject $errors"
	out, err := ps(script)
	if err != nil {
		return fmt.Errorf("restore dns: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// Parse error array from PS — if non-empty, report all failures.
	var errs []struct {
		Iface string `json:"iface"`
		Err   string `json:"err"`
	}
	if err := json.Unmarshal(out, &errs); err == nil && len(errs) > 0 {
		var msgs []string
		for _, e := range errs {
			msgs = append(msgs, fmt.Sprintf("%s: %s", e.Iface, e.Err))
		}
		return fmt.Errorf("restore dns failed for: %s", strings.Join(msgs, "; "))
	}

	_ = os.Remove(config.PrevDNSFile)
	return nil
}
