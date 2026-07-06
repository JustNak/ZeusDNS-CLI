//go:build windows
// +build windows

package windows

import (
	"fmt"
	"path/filepath"
	"strings"
)

// AddToMachinePath appends dir to the system (machine) PATH environment
// variable if it isn't already a member. It shells out to PowerShell's
// [Environment]::SetEnvironmentVariable('Path', ..., 'Machine'), which writes
// HKLM\...\Session Manager\Environment\Path AND broadcasts WM_SETTINGCHANGE —
// so new processes (and newly opened terminals) see the change without a
// reboot. Requires elevation.
//
// Membership is checked case-insensitively against each ';'-separated entry
// (PowerShell's -contains is case-insensitive for strings), matching Windows
// path semantics.
func AddToMachinePath(dir string) error {
	dir = filepath.Clean(dir)
	script := fmt.Sprintf(
		`$d='%[1]s'; `+
			`$p=[Environment]::GetEnvironmentVariable('Path','Machine'); `+
			`$parts=$p -split ';' | Where-Object { $_ -ne '' }; `+
			`if (-not ($parts -contains $d)) { `+
			`[Environment]::SetEnvironmentVariable('Path', (($parts + $d) -join ';'), 'Machine') `+
			`}`,
		psQuote(dir))
	if out, err := ps(script); err != nil {
		return fmt.Errorf("add %s to machine PATH: %w: %s", dir, err, out)
	}
	return nil
}

// RemoveFromMachinePath removes dir from the system (machine) PATH if present.
// No-op when it isn't there. Requires elevation. Broadcasts WM_SETTINGCHANGE so
// new processes drop the entry without a reboot.
func RemoveFromMachinePath(dir string) error {
	dir = filepath.Clean(dir)
	script := fmt.Sprintf(
		`$d='%[1]s'; `+
			`$p=[Environment]::GetEnvironmentVariable('Path','Machine'); `+
			`$parts=$p -split ';' | Where-Object { $_ -ne '' }; `+
			`$new=$parts | Where-Object { $_ -ne $d }; `+
			`if (($parts -join ';') -ne ($new -join ';')) { `+
			`[Environment]::SetEnvironmentVariable('Path', ($new -join ';'), 'Machine') `+
			`}`,
		psQuote(dir))
	if out, err := ps(script); err != nil {
		return fmt.Errorf("remove %s from machine PATH: %w: %s", dir, err, out)
	}
	return nil
}

// psQuote wraps s in the body of a PowerShell single-quoted string, escaping
// any embedded single quote by doubling it (”) is the PS escape inside ”).
func psQuote(s string) string { return strings.ReplaceAll(s, "'", "''") }
