package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"sni-spoofing-go/network"
)

func ConnectFromCLI(listenAddr, connectAddr, fakeSNIOverride string) (*Config, error) {
	return connectFromCLI(listenAddr, connectAddr, fakeSNIOverride, false)
}

func ConnectFromCLIAllowListenPortZero(listenAddr, connectAddr, fakeSNIOverride string) (*Config, error) {
	return connectFromCLI(listenAddr, connectAddr, fakeSNIOverride, true)
}

func connectFromCLI(listenAddr, connectAddr, fakeSNIOverride string, allowListenPortZero bool) (*Config, error) {
	listenHost, listenPortStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen address %q: %w", listenAddr, err)
	}
	listenPort, err := strconv.Atoi(listenPortStr)
	minListenPort := 1
	if allowListenPortZero {
		minListenPort = 0
	}
	if err != nil || listenPort < minListenPort || listenPort > 65535 {
		return nil, fmt.Errorf("invalid listen port in %q", listenAddr)
	}
	connectHost, connectPortStr, err := net.SplitHostPort(connectAddr)
	if err != nil {
		return nil, fmt.Errorf("connect address %q: %w", connectAddr, err)
	}
	connectPort, err := strconv.Atoi(connectPortStr)
	if err != nil || connectPort < 1 || connectPort > 65535 {
		return nil, fmt.Errorf("invalid connect port in %q", connectAddr)
	}
	if listenHost != "" && !network.IsIPv4(listenHost) {
		return nil, fmt.Errorf("listen host must be IPv4 or empty, got %q", listenHost)
	}

	connectHost = strings.TrimSpace(connectHost)
	fakeSNIOverride = strings.TrimSpace(fakeSNIOverride)

	cfg := &Config{
		ListenHost:  listenHost,
		ListenPort:  listenPort,
		ConnectPort: connectPort,
	}

	if network.IsIPv4(connectHost) {
		cfg.ConnectIP = connectHost
		cfg.ConnectIPv4s = []string{connectHost}
		if fakeSNIOverride != "" {
			cfg.FakeSNI = fakeSNIOverride
		} else {
			return nil, fmt.Errorf("with -connect <IPv4>:port, set -fake-sni (no hostname to derive SNI from)")
		}
		return cfg, nil
	}

	ips, err := net.LookupIP(connectHost)
	if err != nil {
		return nil, fmt.Errorf("resolve connect host %q: %w", connectHost, err)
	}
	seen := make(map[string]struct{})
	var ip4s []string
	for _, ip := range ips {
		v := ip.To4()
		if v == nil {
			continue
		}
		s := v.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		ip4s = append(ip4s, s)
	}
	if len(ip4s) == 0 {
		return nil, fmt.Errorf("no IPv4 address for connect host %q", connectHost)
	}
	cfg.ConnectIP = ip4s[0]
	cfg.ConnectIPv4s = ip4s
	if fakeSNIOverride != "" {
		cfg.FakeSNI = fakeSNIOverride
	} else {
		cfg.FakeSNI = connectHost
	}
	return cfg, nil
}
