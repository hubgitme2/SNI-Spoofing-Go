package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type FileOptions struct {
	Listen         string
	Connect        string
	FakeSNI        string
	FakeRepeat     int
	FakeDelay      time.Duration
	AckTimeout     time.Duration
	Injector       string
	UTLS           string
	EnableFragment bool
	FragmentDelay  time.Duration
	SNIChunk       int
	seen           map[string]bool
}

func (o FileOptions) Has(key string) bool {
	return o.seen[normalizeConfigKey(key)]
}

func LoadFileOptions(path string) (FileOptions, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileOptions{}, err
	}
	defer f.Close()

	opts := FileOptions{seen: make(map[string]bool)}
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			k, v, ok = strings.Cut(line, ":")
		}
		if !ok {
			return FileOptions{}, fmt.Errorf("%s:%d: expected key=value", path, lineNo)
		}
		key := normalizeConfigKey(k)
		val := strings.TrimSpace(stripInlineComment(v))
		if err := setFileOption(&opts, key, val); err != nil {
			return FileOptions{}, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
	}
	if err := sc.Err(); err != nil {
		return FileOptions{}, err
	}
	return opts, nil
}

func normalizeConfigKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimLeft(s, "-")
	s = strings.ReplaceAll(s, "_", "-")
	return s
}

func stripInlineComment(s string) string {
	s = strings.TrimSpace(s)
	for i, r := range s {
		if r == '#' || r == ';' {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

func setFileOption(opts *FileOptions, key, val string) error {
	switch key {
	case "listen":
		opts.Listen = val
	case "connect":
		opts.Connect = val
	case "fake-sni":
		opts.FakeSNI = val
	case "fake-repeat":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("fake-repeat: %w", err)
		}
		opts.FakeRepeat = n
	case "fake-delay":
		d, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("fake-delay: %w", err)
		}
		opts.FakeDelay = d
	case "ack-timeout":
		d, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("ack-timeout: %w", err)
		}
		opts.AckTimeout = d
	case "injector":
		opts.Injector = val
	case "utls":
		opts.UTLS = val
	case "enable-fragment":
		b, err := parseConfigBool(val)
		if err != nil {
			return fmt.Errorf("enable-fragment: %w", err)
		}
		opts.EnableFragment = b
	case "fragment-delay":
		d, err := time.ParseDuration(val)
		if err != nil {
			return fmt.Errorf("fragment-delay: %w", err)
		}
		opts.FragmentDelay = d
	case "sni-chunk":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("sni-chunk: %w", err)
		}
		opts.SNIChunk = n
	default:
		return fmt.Errorf("unknown key %q", key)
	}
	opts.seen[key] = true
	return nil
}

func parseConfigBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on", "enable", "enabled":
		return true, nil
	case "0", "false", "no", "n", "off", "disable", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", s)
	}
}
