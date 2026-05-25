package config

import (
	"strings"
	"testing"
)

func TestConnectFromCLI_hostnameDefaultSNI(t *testing.T) {
	cfg, err := ConnectFromCLI("127.0.0.1:8080", "localhost:443", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FakeSNI != "localhost" {
		t.Fatalf("FakeSNI = %q", cfg.FakeSNI)
	}
	if cfg.ConnectIP != "127.0.0.1" {
		t.Fatalf("ConnectIP = %q", cfg.ConnectIP)
	}
	if len(cfg.ConnectIPv4s) != 1 || cfg.ConnectIPv4s[0] != "127.0.0.1" {
		t.Fatalf("ConnectIPv4s = %v", cfg.ConnectIPv4s)
	}
}

func TestConnectFromCLI_hostnameFakeSNIOverride(t *testing.T) {
	cfg, err := ConnectFromCLI("127.0.0.1:8080", "localhost:443", "other.test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FakeSNI != "other.test" {
		t.Fatalf("FakeSNI = %q", cfg.FakeSNI)
	}
}

func TestConnectFromCLI_IPRequiresFakeSNI(t *testing.T) {
	_, err := ConnectFromCLI("127.0.0.1:8080", "198.51.100.2:443", "")
	if err == nil {
		t.Fatal("expected error for IPv4 connect without -fake-sni")
	}
	if !strings.Contains(err.Error(), "fake-sni") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestConnectFromCLI_IPWithFakeSNI(t *testing.T) {
	cfg, err := ConnectFromCLI("127.0.0.1:8080", "198.51.100.2:443", "allowed.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FakeSNI != "allowed.example.com" || cfg.ConnectIP != "198.51.100.2" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if len(cfg.ConnectIPv4s) != 1 || cfg.ConnectIPv4s[0] != "198.51.100.2" {
		t.Fatalf("ConnectIPv4s = %v", cfg.ConnectIPv4s)
	}
}

func TestConnectFromCLIListenPortZeroOnlyWhenAllowed(t *testing.T) {
	if _, err := ConnectFromCLI("127.0.0.1:0", "198.51.100.2:443", "allowed.example.com"); err == nil {
		t.Fatal("expected listen port 0 to fail in normal mode")
	}
	cfg, err := ConnectFromCLIAllowListenPortZero("127.0.0.1:0", "198.51.100.2:443", "allowed.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenPort != 0 {
		t.Fatalf("ListenPort = %d, want 0", cfg.ListenPort)
	}
}
