package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFileOptions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	data := `
listen = 127.0.0.1:8080
connect = example.com:443
fake_sni = allowed.example.com
fake-repeat = 2
fake-delay = 5ms
ack-timeout = 3s
injector = passive
utls = none
enable-fragment = yes
fragment-delay = 250ms
sni-chunk = 4
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err := LoadFileOptions(path)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Listen != "127.0.0.1:8080" || opts.Connect != "example.com:443" || opts.FakeSNI != "allowed.example.com" {
		t.Fatalf("address options = %+v", opts)
	}
	if opts.FakeRepeat != 2 || opts.FakeDelay != 5*time.Millisecond || opts.AckTimeout != 3*time.Second {
		t.Fatalf("timing/repeat options = %+v", opts)
	}
	if opts.Injector != "passive" {
		t.Fatalf("injector option = %q", opts.Injector)
	}
	if opts.UTLS != "none" || !opts.EnableFragment || opts.FragmentDelay != 250*time.Millisecond || opts.SNIChunk != 4 {
		t.Fatalf("fragment/utls options = %+v", opts)
	}
}

func TestLoadFileOptionsUnknownKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(path, []byte("wat = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFileOptions(path); err == nil {
		t.Fatal("expected error for unknown key")
	}
}
