package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"sni-spoofing-go/config"
	"sni-spoofing-go/injection"
	"sni-spoofing-go/packet"
)

func TestConfigPathFromArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-config", "custom.ini"}, "custom.ini"},
		{[]string{"--config", "custom.ini"}, "custom.ini"},
		{[]string{"-config=custom.ini"}, "custom.ini"},
		{[]string{"--config=custom.ini"}, "custom.ini"},
	} {
		got, ok, err := configPathFromArgs(tc.args)
		if err != nil {
			t.Fatalf("configPathFromArgs(%v): %v", tc.args, err)
		}
		if !ok || got != tc.want {
			t.Fatalf("configPathFromArgs(%v) = %q, %v; want %q, true", tc.args, got, ok, tc.want)
		}
	}
}

func TestApplyOptionDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(path, []byte(`
listen = 127.0.0.1:8080
connect = example.com:443
utls = none
fake-delay = 0s
enable-fragment = true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	fileOpts, err := config.LoadFileOptions(path)
	if err != nil {
		t.Fatal(err)
	}

	var listen, connect, fakeSNI, utls string
	var fakeRepeat, sniChunk int
	var fakeDelay, ackTimeout, fragmentDelay time.Duration
	var enableFragment bool

	var injectorMode string
	applyOptionDefaults(fileOpts, &listen, &connect, &fakeSNI, &utls, &injectorMode, &fakeRepeat, &fakeDelay, &ackTimeout, &enableFragment, &fragmentDelay, &sniChunk)

	if listen != "127.0.0.1:8080" || connect != "example.com:443" || utls != "none" {
		t.Fatalf("string defaults = %q %q %q", listen, connect, utls)
	}
	if fakeRepeat != 1 || fakeDelay != 0 || ackTimeout != 2*time.Second {
		t.Fatalf("numeric defaults repeat=%d fakeDelay=%v ackTimeout=%v", fakeRepeat, fakeDelay, ackTimeout)
	}
	if !enableFragment || fragmentDelay != 500*time.Millisecond || sniChunk != packet.DefaultSNIChunkBytes {
		t.Fatalf("fragment defaults enable=%v delay=%v chunk=%d", enableFragment, fragmentDelay, sniChunk)
	}
}

func TestDefaultTestListenAddr(t *testing.T) {
	if got := defaultTestListenAddr(); got != "127.0.0.1:0" {
		t.Fatalf("default test listen addr = %q", got)
	}
}

func TestEffectiveListenAddr(t *testing.T) {
	if got := effectiveListenAddr("0.0.0.0:40443", true); got != defaultTestListenAddr() {
		t.Fatalf("test listen addr = %q", got)
	}
	if got := effectiveListenAddr("0.0.0.0:40443", false); got != "0.0.0.0:40443" {
		t.Fatalf("normal listen addr = %q", got)
	}
}

func TestParseCloudflareTraceIP(t *testing.T) {
	got, err := parseCloudflareTraceIP("colo=FRA\nip=94.101.178.10\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "94.101.178.10" {
		t.Fatalf("ip = %q", got)
	}
	if _, err := parseCloudflareTraceIP("colo=FRA\n"); err == nil {
		t.Fatal("expected missing ip error")
	}
}

func TestParseArvanTraceIP(t *testing.T) {
	got, err := parseArvanTraceIP("<html>Your IP: 94.101.178.10</html>")
	if err != nil {
		t.Fatal(err)
	}
	if got != "94.101.178.10" {
		t.Fatalf("ip = %q", got)
	}
	if _, err := parseArvanTraceIP("<html>no ip</html>"); err == nil {
		t.Fatal("expected missing ip error")
	}
}

func TestLoopbackListenAddr(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"0.0.0.0:40443", "127.0.0.1:40443"},
		{":40443", "127.0.0.1:40443"},
		{"127.0.0.1:40443", "127.0.0.1:40443"},
	} {
		if got := loopbackListenAddr(tc.in); got != tc.want {
			t.Fatalf("loopbackListenAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMethodMatrixCases(t *testing.T) {
	if methodMatrixCaseDelay <= 0 {
		t.Fatal("method matrix case delay must be positive")
	}
	cases := methodMatrixCases()
	if len(cases) != 24 {
		t.Fatalf("case count = %d, want 24", len(cases))
	}

	seen := make(map[string]bool)
	for _, tc := range cases {
		opts := tc.proxyOptions(injection.InjectorModeActive)
		if opts.ackTimeout != 3*time.Second || opts.fakeDelay != 10*time.Millisecond ||
			opts.fragmentDelay != 10*time.Millisecond || opts.sniChunk != 3 {
			t.Fatalf("wrong constants for %s: %+v", tc.String(), opts)
		}
		seen[tc.String()] = true
	}
	for _, want := range []string{
		"utls=none repeat=1 fragment=off",
		"utls=firefox repeat=2 fragment=on",
		"utls=edge repeat=2 fragment=on",
	} {
		if !seen[want] {
			t.Fatalf("missing matrix case %q", want)
		}
	}
}
