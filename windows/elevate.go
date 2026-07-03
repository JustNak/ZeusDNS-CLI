//go:build windows
// +build windows

package windows

import "golang.org/x/sys/windows"

// IsElevated reports whether the current process is running with an elevated
// (administrator) token. Used to gate operations that require admin rights
// (service install/uninstall/start/stop, system DNS changes, WFP) so a
// non-admin run gets a clear message instead of a raw "Access is denied" from
// the Service Control Manager.
func IsElevated() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}
