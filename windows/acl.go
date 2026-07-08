//go:build windows
// +build windows

package windows

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/JustNak/ZeusDNS-CLI/config"
)

// protectPath applies a restrictive DACL to the given file or directory:
//   - Grants GENERIC_ALL to SYSTEM
//   - Grants GENERIC_ALL to Administrators
//   - Removes inherited permissions (PROTECTED_DACL_SECURITY_INFORMATION)
//
// For directories, the ACEs are marked inheritable so that child objects
// created later (files, subdirs) automatically inherit the restricted ACL.
// Call this on the config directory once at service start; individual files
// are also protected explicitly after creation.
func protectPath(path string, isDir bool) error {

	// Build well-known SIDs for SYSTEM and Administrators.
	sidSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("create SYSTEM SID: %w", err)
	}
	sidAdmins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("create Administrators SID: %w", err)
	}

	// Inheritance flags: for directories, child files and subdirs inherit.
	inherit := uint32(windows.NO_INHERITANCE)
	if isDir {
		inherit = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}

	// Build EXPLICIT_ACCESS entries.
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inherit,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sidSystem),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inherit,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sidAdmins),
			},
		},
	}

	// Build a new ACL from these entries (nil oldACL = start from scratch).
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build DACL for %s: %w", path, err)
	}

	// Apply the DACL with PROTECTED flag to block inherited permissions.
	const si = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		si,
		nil, // owner SID — unchanged
		nil, // group SID — unchanged
		acl, // new DACL
		nil, // SACL — unchanged
	); err != nil {
		return fmt.Errorf("apply DACL to %s: %w", path, err)
	}

	return nil
}

// knownConfigFiles returns the list of well-known files under DefaultDir that
// should have restrictive ACLs. The log file is omitted because its path is
// dynamic (set by the user in config.yaml) and is resolved at service start.
func knownConfigFiles() []string {
	return []string{
		config.DefaultFile,    // config.yaml
		config.PrevDNSFile,    // prev_dns.json
	}
}

// ProtectConfigDir applies a restrictive ACL to the config directory
// (C:\ProgramData\ZeusDNS) so that inherited child permissions are blocked
// and only SYSTEM + Administrators have access. It also protects any existing
// known files within the directory.
//
// Must be called after the directory and/or files have been created. It is
// safe to call repeatedly (idempotent). On first call the directory's DACL
// is replaced; on subsequent calls it is a no-op (the ACL is already set).
func ProtectConfigDir() error {
	// 1. Protect the directory itself with inheritable ACEs.
	if err := protectPath(config.DefaultDir, true); err != nil {
		return fmt.Errorf("protect config dir: %w", err)
	}

	// 2. Protect existing known files (non-inheritable).
	for _, fp := range knownConfigFiles() {
		if _, err := os.Stat(fp); err == nil {
			if err := protectPath(fp, false); err != nil {
				return fmt.Errorf("protect %s: %w", filepath.Base(fp), err)
			}
		}
	}

	return nil
}

// ProtectFile applies a restrictive DACL to a single file. Useful for
// protecting the log file whose path is dynamic.
func ProtectFile(path string) error {
	return protectPath(path, false)
}

// RedactURL masks the path component of a DoH upstream URL for safe display
// in logs and error messages. DoT URLs (tls://host:port) have no path
// component and are returned verbatim.
//
// Examples:
//
//	https://dns.controld.com/abc123def456  →  https://dns.controld.com/***
//	https://dns.example.com/dns-query      →  https://dns.example.com/***
//	tls://dns.example.com:853              →  tls://dns.example.com:853
func RedactURL(raw string) string {
	// Only redact https:// URLs (DoH may have tokens in the path).
	if len(raw) < 8 || raw[:8] != "https://" {
		return raw
	}
	// Find the third '/' (after https://)
	slash := 0
	count := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] == '/' {
			count++
			if count == 3 {
				slash = i
				break
			}
		}
	}
	if slash == 0 || slash == len(raw)-1 {
		// No path or empty path — nothing to redact.
		return raw
	}
	return raw[:slash+1] + "***"
}
