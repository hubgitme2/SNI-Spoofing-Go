//go:build linux || darwin

package main

import "os"

func isPrivileged() (bool, error) {
	return os.Geteuid() == 0, nil
}

func privilegeHint() string {
	return "run as root"
}
