// +build windows

package privileges

import "golang.org/x/sys/windows"

var processToken windows.Token

// Revert to self terminates the impersonation of a client application
func revertToSelf() error {
	processToken = windows.Token(0)
	return windows.RevertToSelf()
}

// This function attempts to enable a privilege
func EnablePrivilege(privilege string) error {
	return nil
}
