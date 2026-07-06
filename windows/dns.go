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

// getDhcpState queries the DHCP (Obtain DNS server address automatically) flag
// for every IPv4 interface. The result is used by getSystemDNS to annotate DNS
// entries so RestoreSystemDNS can reset to automatic DHCP DNS instead of
// statically rewriting saved server IPs.
func getDhcpState() (map[string]string, error) {
	// .ToString() is REQUIRED: ConvertTo-Json serializes the .Dhcp enum
	// (Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Dhcp)
	// as its integer value (1/0), not "Enabled"/"Disabled". Without the cast
	// the Dhcp field unmarshals as a number, parseDhcpJSON's normalization
	// still maps 1→"Enabled" (defensive), but emitting the string is canonical.
	script := `Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias,@{n='Dhcp';e={$_.Dhcp.ToString()}} | ConvertTo-Json -Compress -Depth 3`
	out, err := ps(script)
	if err != nil {
		return nil, fmt.Errorf("Get-NetIPInterface: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return parseDhcpJSON(out), nil
}

// getSystemDNS reads the current IPv4 DNS server addresses per interface and
// annotates each entry with its DHCP state so RestoreSystemDNS can distinguish
// "automatic DHCP DNS" from "manually-set static DNS".
func getSystemDNS() ([]ifaceDNS, error) {
	script := `Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress -Depth 3`
	out, err := ps(script)
	if err != nil {
		return nil, fmt.Errorf("Get-DnsClientServerAddress: %w: %s", err, strings.TrimSpace(string(out)))
	}
	entries, err := normalizePSJSON(out)
	if err != nil {
		return nil, err
	}
	// Annotate each entry with DHCP state so RestoreSystemDNS can distinguish
	// "automatic DHCP DNS" from "manually-set static DNS".
	dhcpMap, dhcpErr := getDhcpState()
	if dhcpErr != nil {
		// Non-fatal: old systems or constrained runtimes may lack
		// Get-NetIPInterface; restore degrades to static rewrite instead of
		// -ResetServerAddresses, which is safe albeit imperfect.
		return entries, nil
	}
	for i := range entries {
		entries[i].Dhcp = dhcpMap[entries[i].InterfaceAlias]
	}
	return entries, nil
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
		// DHCP-aware restore: interfaces whose IP config is DHCP ("Obtain DNS
		// server address automatically") should use -ResetServerAddresses to
		// return to automatic DNS, not a static rewrite.
		//
		// Blind spot: a DHCP-IP interface with a manual DNS override
		// (rare power-user setup) will be reset to automatic DNS. This is the
		// correct target state for this tool — ZeusDNS is the user's chosen
		// DNS manager and should own the DNS config.
		switch {
		case e.Dhcp == "Enabled":
			script = fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias %s -ResetServerAddresses`, quoteAlias(e.InterfaceAlias))
		case len(e.ServerAddresses) == 0:
			script = fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias %s -ResetServerAddresses`, quoteAlias(e.InterfaceAlias))
		default:
			script = fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias %s -ServerAddresses '%s'`, quoteAlias(e.InterfaceAlias), strings.Join(e.ServerAddresses, ","))
		}
		if out, err := ps(script); err != nil {
			return fmt.Errorf("restore dns %s: %w: %s", e.InterfaceAlias, err, strings.TrimSpace(string(out)))
		}
	}
	_ = os.Remove(config.PrevDNSFile)
	return nil
}
