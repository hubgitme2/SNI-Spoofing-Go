//go:build !darwin

package main

import "sni-spoofing-go/injection"

func defaultInjectorMode() injection.InjectorMode {
	return injection.InjectorModeActive
}
