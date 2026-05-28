//go:build windows

package main

import "golang.org/x/sys/windows"

func isPrivileged() (bool, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false, err
	}
	defer token.Close()
	return token.IsElevated(), nil
}

func privilegeHint() string {
	return "run as Administrator"
}
