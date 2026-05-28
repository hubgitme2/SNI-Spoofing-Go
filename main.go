// TLS proxy: fake ClientHello injection (wrong-seq) + optional real CH fragmentation. IPv4 only; needs admin/root.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"sni-spoofing-go/config"
	"sni-spoofing-go/injection"
	"sni-spoofing-go/network"
	"sni-spoofing-go/packet"
)

const (
	firstClientHelloTimeout = 10 * time.Second
	methodMatrixCaseDelay   = 2 * time.Second
)

func defaultTestListenAddr() string {
	return "127.0.0.1:0"
}

func effectiveListenAddr(listen string, testMethod bool) string {
	if testMethod {
		return defaultTestListenAddr()
	}
	return listen
}

func usage() {
	exe := os.Args[0]
	w := os.Stderr
	fmt.Fprintf(w, "SNI-Spoofing — fake TLS ClientHello (SNI) injection proxy. IPv4 only; run as Administrator / root.\n\n")
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  %s -listen <addr> -connect <addr> [options]\n\n", exe)
	fmt.Fprintf(w, "Required:\n")
	fmt.Fprintf(w, "  -listen <host:port>   listen address (host optional, e.g. :8080)\n")
	fmt.Fprintf(w, "  -connect <host:port>  upstream; hostname (SNI from host) or IPv4 (needs -fake-sni)\n\n")
	fmt.Fprintf(w, "Optional:\n")
	fmt.Fprintf(w, "  -config <path>       INI config file (default: ./config.ini if it exists)\n")
	fmt.Fprintf(w, "  -test              run e2e method test matrix for the selected -connect/-fake-sni pair, then exit\n")
	fmt.Fprintf(w, "  -fake-sni <hostname>  SNI in the injected ClientHello (overrides -connect hostname)\n")
	fmt.Fprintf(w, "  -fake-repeat <n>      fake ClientHello injections before real traffic (default 1)\n")
	fmt.Fprintf(w, "  -fake-delay          delay after fake injection (default 2ms)\n")
	fmt.Fprintf(w, "  -ack-timeout         max wait for server ACK after fake injection (default 2s)\n")
	fmt.Fprintf(w, "  -utls <name>         TLS fingerprint (default: firefox); use \"none\" for legacy template; list below\n")
	fmt.Fprintf(w, "  -enable-fragment     fragment real ClientHello (prefix / SNI chunks / suffix); default false\n")
	fmt.Fprintf(w, "  -fragment-delay      delay between TCP segments when ClientHello is split (default 500ms)\n")
	fmt.Fprintf(w, "  -sni-chunk            SNI bytes per TCP write after prefix (default 3; 0 = whole name in one write)\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "Examples:\n")
	fmt.Fprintf(w, "  %s -listen 127.0.0.1:8080 -connect example.com:443\n", exe)
	fmt.Fprintf(w, "  %s -listen 127.0.0.1:8080 -connect 198.51.100.2:443 -fake-sni allowed.example.com\n\n", exe)
	fmt.Fprintf(w, "Valid -utls names:\n\n")
	fmt.Fprintf(w, "%s", packet.UTLSHelpGroupedCSV())
	fmt.Fprintf(w, "\nDefault when -utls is omitted: %s. Use -utls none for the legacy fixed ClientHello.\n\n", packet.DefaultUTLSSummary())
	fmt.Fprintf(w, "Options:\n")
	flag.PrintDefaults()
}

func main() {
	fileOpts, configPath, err := loadInitialFileOptions(os.Args[1:])
	if err != nil {
		log.Fatal("Invalid config file: ", err)
	}

	flag.Usage = usage
	var optListen, optConnect, optFakeSNI, optUTLS string
	var enableFragment bool
	var injectorMode string
	var fragmentDelay time.Duration
	var sniChunk int
	var fakeRepeat int
	var ackTimeout time.Duration
	var fakeDelay time.Duration
	var testMode bool
	applyOptionDefaults(fileOpts, &optListen, &optConnect, &optFakeSNI, &optUTLS, &injectorMode, &fakeRepeat, &fakeDelay, &ackTimeout, &enableFragment, &fragmentDelay, &sniChunk)

	flag.StringVar(&configPath, "config", configPath, "INI config file (default: ./config.ini if it exists)")
	flag.BoolVar(&testMode, "test", false, "run e2e method test matrix for the selected upstream/decoy SNI pair, then exit")
	flag.StringVar(&injectorMode, "injector", string(defaultInjectorMode()), "packet injector backend: active or passive")
	flag.StringVar(&optListen, "listen", optListen, "listen address host:port (required)")
	flag.StringVar(&optConnect, "connect", optConnect, "upstream host:port (required)")
	flag.StringVar(&optFakeSNI, "fake-sni", optFakeSNI, "injected ClientHello SNI (optional if -connect uses a hostname)")
	flag.IntVar(&fakeRepeat, "fake-repeat", fakeRepeat, "number of wrong-seq fake ClientHello injections before real traffic")
	flag.DurationVar(&fakeDelay, "fake-delay", fakeDelay, "delay after fake injection (0 = none)")
	flag.StringVar(&optUTLS, "utls", optUTLS, "TLS fingerprint preset (see usage above; e.g. chrome_120, firefox, none)")
	flag.BoolVar(&enableFragment, "enable-fragment", enableFragment, "after fake SNI, read real ClientHello: send prefix, then SNI chunks, then suffix")
	flag.DurationVar(&fragmentDelay, "fragment-delay", fragmentDelay, "delay between TCP segments when fake or real ClientHello is split (MSS / chunking)")
	flag.IntVar(&sniChunk, "sni-chunk", sniChunk, "SNI hostname bytes per TCP write (0 = entire hostname in one write)")
	flag.DurationVar(&ackTimeout, "ack-timeout", ackTimeout, "timeout waiting for server ACK after fake injection")
	flag.Parse()

	fakeSNIArg := strings.TrimSpace(optFakeSNI)

	args := flag.Args()
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected arguments: %q\n", args)
		fmt.Fprintln(os.Stderr)
		usage()
		os.Exit(2)
	}
	requirePrivilegedOrExit()
	if testMode {
		optListen = effectiveListenAddr(optListen, true)
	}
	if strings.TrimSpace(optListen) == "" || strings.TrimSpace(optConnect) == "" {
		log.Fatal("required config: -listen and -connect (or listen/connect in config.ini)")
	}
	if fakeRepeat < 1 {
		log.Fatal("-fake-repeat must be at least 1")
	}
	if sniChunk < 0 {
		log.Fatal("-sni-chunk must be >= 0 (0 = whole hostname in one write)")
	}
	if ackTimeout <= 0 {
		log.Fatal("-ack-timeout must be positive (e.g. 2s, 5s, 1m)")
	}
	injector, err := parseInjectorMode(injectorMode)
	if err != nil {
		log.Fatal(err)
	}
	var cfg *config.Config
	if testMode {
		cfg, err = config.ConnectFromCLIAllowListenPortZero(optListen, optConnect, fakeSNIArg)
	} else {
		cfg, err = config.ConnectFromCLI(optListen, optConnect, fakeSNIArg)
	}
	if err != nil {
		log.Fatal("Invalid configuration: ", err)
	}

	if strings.TrimSpace(optUTLS) != "" {
		cfg.UTLSClientHello = optUTLS
	}
	if !testMode && !packet.IsLegacyUTLS(cfg.UTLSClientHello) {
		if _, err := packet.ParseClientHelloID(cfg.UTLSClientHello); err != nil {
			log.Fatal("Invalid -utls: ", err)
		}
	}

	if !network.IsIPv4(cfg.ConnectIP) {
		log.Fatalf("upstream must resolve to IPv4 (IPv6 is not supported): %q", cfg.ConnectIP)
	}
	if len(cfg.ConnectIPv4s) == 0 {
		log.Fatal("internal error: no ConnectIPv4s after resolve")
	}
	if cfg.ListenHost != "" && !network.IsIPv4(cfg.ListenHost) {
		log.Fatalf("LISTEN host must be IPv4 or empty (IPv6 is not supported): %q", cfg.ListenHost)
	}

	proxyOpts := proxyOptions{
		fakeRepeat:     fakeRepeat,
		fakeDelay:      fakeDelay,
		enableFragment: enableFragment,
		fragmentDelay:  fragmentDelay,
		sniChunk:       sniChunk,
		ackTimeout:     ackTimeout,
		injector:       injector,
	}
	if testMode {
		if err := runMethodMatrix(cfg, injector); err != nil {
			fmt.Fprintln(os.Stderr, err)
			waitForExitKey()
			os.Exit(1)
		}
		waitForExitKey()
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Print("shutdown")
	}()
	if err := runProxy(ctx, cfg, proxyOpts, nil); err != nil {
		log.Fatal(err)
	}
}

type proxyOptions struct {
	fakeRepeat     int
	fakeDelay      time.Duration
	enableFragment bool
	fragmentDelay  time.Duration
	sniChunk       int
	ackTimeout     time.Duration
	quiet          bool
	injector       injection.InjectorMode
}

func parseInjectorMode(s string) (injection.InjectorMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(injection.InjectorModeActive):
		return injection.InjectorModeActive, nil
	case string(injection.InjectorModePassive):
		return injection.InjectorModePassive, nil
	default:
		return "", fmt.Errorf("invalid -injector %q (want active or passive)", s)
	}
}

func requirePrivilegedOrExit() {
	ok, err := isPrivileged()
	if err == nil && ok {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Privilege check failed: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "This program needs elevated privileges; please %s.\n", privilegeHint())
	waitForExitKey()
	os.Exit(1)
}

type proxyReady struct {
	listenAddr string
	err        error
}

func runProxy(ctx context.Context, cfg *config.Config, opts proxyOptions, ready chan<- proxyReady) error {
	interfaceIPv4 := network.GetDefaultInterfaceIPv4(cfg.ConnectIP)
	if interfaceIPv4 == "" {
		return fmt.Errorf("failed to detect local interface IPv4 address")
	}
	if !opts.quiet {
		log.Printf("iface: %s", interfaceIPv4)
	}

	fakeInjector, err := injection.NewFakeTcpInjector(interfaceIPv4, cfg.ConnectIPv4s, uint16(cfg.ConnectPort), opts.injector)
	if err != nil {
		return fmt.Errorf("failed to create injector: %w", err)
	}
	defer fakeInjector.Close()

	injectorErr := make(chan error, 1)
	go func() {
		if err := fakeInjector.Start(); err != nil {
			injectorErr <- err
		}
	}()
	if err := fakeInjector.WaitInjectorReady(); err != nil {
		if ready != nil {
			ready <- proxyReady{err: err}
		}
		return fmt.Errorf("injector: %w", err)
	}

	listenAddr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.ListenPort))
	listener, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		if ready != nil {
			ready <- proxyReady{err: err}
		}
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		fakeInjector.Close()
	}()

	if !opts.quiet {
		log.Printf("listen: %s", listener.Addr().String())
	}
	if ready != nil {
		ready <- proxyReady{listenAddr: listener.Addr().String()}
	}

	for {
		incomingSock, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			select {
			case err := <-injectorErr:
				return fmt.Errorf("injector: %w", err)
			default:
			}
			if !opts.quiet {
				log.Printf("Accept error: %v", err)
			}
			continue
		}

		if tc, ok := incomingSock.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(11 * time.Second)
		}

		go handleConnection(incomingSock, cfg, interfaceIPv4, cfg.FakeSNI, fakeInjector, opts)
	}
}

func handleConnection(
	incomingSock net.Conn,
	cfg *config.Config,
	interfaceIPv4 string,
	fakeSNI string,
	fakeInjector injection.TCPInjector,
	opts proxyOptions,
) {
	defer func() {
		if r := recover(); r != nil {
			if !opts.quiet {
				log.Printf("panic in handle: %v", r)
			}
		}
	}()

	fakeData, err := buildFakeClientHello(fakeSNI, cfg.UTLSClientHello)
	if err != nil {
		if !opts.quiet {
			log.Printf("ClientHello: %v", err)
		}
		incomingSock.Close()
		return
	}

	outgoingSock, conn, _, err := dialOutgoing(
		interfaceIPv4, cfg.ConnectIP, cfg.ConnectPort,
		fakeData, "wrong_seq", opts.fakeRepeat, opts.fakeDelay, opts.fragmentDelay, incomingSock, fakeInjector,
	)
	if err != nil {
		if !opts.quiet {
			log.Printf("Failed to connect to %s:%d: %v", cfg.ConnectIP, cfg.ConnectPort, err)
		}
		incomingSock.Close()
		return
	}

	conn.Mu.Lock()
	conn.Sock = outgoingSock
	conn.Mu.Unlock()

	if tc, ok := outgoingSock.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(11 * time.Second)
	}

	select {
	case msg := <-conn.T2aChan:
		if msg == "unexpected_close" {
			if !opts.quiet {
				log.Printf("proxy: injector aborted handshake")
			}
			stopMonitoring(fakeInjector, conn)
			closePair(outgoingSock, incomingSock)
			return
		}
		if msg != "fake_data_ack_recv" {
			if !opts.quiet {
				log.Printf("unexpected t2a msg: %q", msg)
			}
			stopMonitoring(fakeInjector, conn)
			closePair(outgoingSock, incomingSock)
			return
		}
	case <-time.After(opts.ackTimeout):
		if !opts.quiet {
			log.Printf("proxy: ACK timeout after %v", opts.ackTimeout)
		}
		stopMonitoring(fakeInjector, conn)
		closePair(outgoingSock, incomingSock)
		return
	}

	stopMonitoring(fakeInjector, conn)

	if opts.fakeDelay > 0 {
		time.Sleep(opts.fakeDelay)
	}

	if opts.enableFragment {
		if err := forwardFragmentedClientHello(incomingSock, outgoingSock, opts.fragmentDelay, opts.sniChunk, false, !opts.quiet); err != nil {
			if !opts.quiet {
				log.Printf("ClientHello fragment: %v", err)
			}
			closePair(outgoingSock, incomingSock)
			return
		}
	}

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		relay(outgoingSock, incomingSock)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		relay(incomingSock, outgoingSock)
	}()

	<-done
	closePair(outgoingSock, incomingSock)
	<-done
}

func buildFakeClientHello(fakeSNI, utlsName string) ([]byte, error) {
	if packet.IsLegacyUTLS(utlsName) {
		return packet.BuildLegacyClientHelloRecord(fakeSNI)
	}
	clientHelloID, err := packet.ParseClientHelloID(utlsName)
	if err != nil {
		return nil, err
	}
	return packet.BuildClientHelloRecord(fakeSNI, clientHelloID)
}

type methodMatrixCase struct {
	UTLS           string
	FakeRepeat     int
	EnableFragment bool
}

func methodMatrixCases() []methodMatrixCase {
	utlsNames := []string{"none", "firefox", "chrome", "safari", "ios", "edge"}
	repeats := []int{1, 2}
	fragments := []bool{false, true}

	out := make([]methodMatrixCase, 0, len(utlsNames)*len(repeats)*len(fragments))
	for _, utlsName := range utlsNames {
		for _, repeat := range repeats {
			for _, enableFragment := range fragments {
				out = append(out, methodMatrixCase{
					UTLS:           utlsName,
					FakeRepeat:     repeat,
					EnableFragment: enableFragment,
				})
			}
		}
	}
	return out
}

func (c methodMatrixCase) proxyOptions(injector injection.InjectorMode) proxyOptions {
	return proxyOptions{
		fakeRepeat:     c.FakeRepeat,
		fakeDelay:      10 * time.Millisecond,
		enableFragment: c.EnableFragment,
		fragmentDelay:  10 * time.Millisecond,
		sniChunk:       3,
		ackTimeout:     3 * time.Second,
		quiet:          true,
		injector:       injector,
	}
}

func (c methodMatrixCase) String() string {
	fragment := "off"
	if c.EnableFragment {
		fragment = "on"
	}
	return fmt.Sprintf("utls=%s repeat=%d fragment=%s", c.UTLS, c.FakeRepeat, fragment)
}

func runMethodMatrix(cfg *config.Config, injector injection.InjectorMode) error {
	fmt.Println("Preflight")
	ok, err := checkMethodPreconditions(cfg.ConnectIP, cfg.FakeSNI)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Println("  warning: internal IP unavailable; running e2e matrix anyway")
	}
	fmt.Println()
	fmt.Println("Matrix")
	fmt.Printf("%-8s %-11s %-8s %-6s\n", "UTLS", "Fake-Repeat", "Fragment", "Result")

	cases := methodMatrixCases()
	failed := 0
	for i, tc := range cases {
		if i > 0 {
			time.Sleep(methodMatrixCaseDelay)
		}
		caseCfg := *cfg
		caseCfg.UTLSClientHello = tc.UTLS
		if !packet.IsLegacyUTLS(caseCfg.UTLSClientHello) {
			if _, err := packet.ParseClientHelloID(caseCfg.UTLSClientHello); err != nil {
				return fmt.Errorf("method matrix: invalid uTLS %q: %w", caseCfg.UTLSClientHello, err)
			}
		}

		if err := runQuietly(func() error {
			return runMethodE2E(&caseCfg, tc.proxyOptions(injector))
		}); err != nil {
			fmt.Printf("%-8s %-11d %-8s %-6s\n", tc.UTLS, tc.FakeRepeat, fragmentLabel(tc.EnableFragment), "FAIL")
			failed++
			continue
		}
		fmt.Printf("%-8s %-11d %-8s %-6s\n", tc.UTLS, tc.FakeRepeat, fragmentLabel(tc.EnableFragment), "PASS")
	}

	if failed > 0 {
		return fmt.Errorf("method matrix: %d/%d failed", failed, len(cases))
	}
	fmt.Printf("\nAll %d cases passed.\n", len(cases))
	return nil
}

func checkMethodPreconditions(connectIP, fakeSNI string) (bool, error) {
	traceIP, err := fetchFakeSNITraceIP(connectIP, fakeSNI)
	if err != nil {
		return false, fmt.Errorf("method test: fake-SNI trace failed: %w; method won't work", err)
	}
	fmt.Printf("  external IP: %s\n", traceIP)

	internalIP, err := fetchArvanTraceIP()
	if err != nil {
		fmt.Printf("  internal IP: unavailable\n")
		return false, nil
	}
	fmt.Printf("  internal IP: %s\n", internalIP)

	if traceIP == internalIP {
		fmt.Println("  result: IPs match; running e2e matrix")
	} else {
		return false, fmt.Errorf("method test: IPs differ (%s != %s); method won't work", traceIP, internalIP)
	}
	return true, nil
}

func fragmentLabel(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}

func runQuietly(fn func() error) error {
	prev := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prev)
	return fn()
}

func waitForExitKey() {
	fmt.Fprint(os.Stderr, "\nPress Enter to exit...")
	_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
	fmt.Fprintln(os.Stderr)
}

func runMethodE2E(cfg *config.Config, opts proxyOptions) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan proxyReady, 1)
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- runProxy(ctx, cfg, opts, ready)
	}()

	var listenAddr string
	select {
	case r := <-ready:
		if r.err != nil {
			return fmt.Errorf("method test: tunnel start failed: %w", r.err)
		}
		listenAddr = loopbackListenAddr(r.listenAddr)
	case err := <-proxyErr:
		return fmt.Errorf("method test: tunnel stopped before ready: %w", err)
	case <-time.After(15 * time.Second):
		return fmt.Errorf("method test: tunnel start timeout")
	}

	if err := fetchE2EDNSJSON(listenAddr); err != nil {
		return fmt.Errorf("e2e request failed: %w", err)
	}
	cancel()
	<-proxyErr
	return nil
}

func fetchFakeSNITraceIP(connectIP, fakeSNI string) (string, error) {
	host := strings.TrimSpace(fakeSNI)
	if host == "" {
		return "", fmt.Errorf("empty fake SNI")
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/?#") {
		return "", fmt.Errorf("fake SNI must be a hostname, got %q", fakeSNI)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, networkName, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(connectIP, "443"))
		},
		TLSClientConfig:       testTLSConfig(host),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return parseCloudflareTraceIP(string(body))
}

var (
	testRootCAsOnce sync.Once
	testRootCAs     *x509.CertPool
)

func testTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		RootCAs:    methodTestRootCAs(),
	}
}

func methodTestRootCAs() *x509.CertPool {
	testRootCAsOnce.Do(func() {
		pool, err := x509.SystemCertPool()
		systemOK := err == nil && pool != nil
		if !systemOK {
			pool = x509.NewCertPool()
		}

		appended := appendCertFiles(pool, caBundleCandidates())
		appended = appendCertDirs(pool, caDirCandidates()) || appended
		if systemOK || appended {
			testRootCAs = pool
		}
	})
	return testRootCAs
}

func caBundleCandidates() []string {
	return []string{
		os.Getenv("SSL_CERT_FILE"),
		"/data/data/com.termux/files/usr/etc/tls/cert.pem",
		"/data/data/com.termux/files/usr/etc/ssl/cert.pem",
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/tls/cacert.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	}
}

func caDirCandidates() []string {
	return []string{
		os.Getenv("SSL_CERT_DIR"),
		"/data/data/com.termux/files/usr/etc/tls/certs",
		"/data/data/com.termux/files/usr/etc/ssl/certs",
		"/etc/ssl/certs",
		"/system/etc/security/cacerts",
	}
}

func appendCertFiles(pool *x509.CertPool, paths []string) bool {
	appended := false
	for _, path := range paths {
		if appendCertFile(pool, path) {
			appended = true
		}
	}
	return appended
}

func appendCertDirs(pool *x509.CertPool, dirs []string) bool {
	appended := false
	for _, dir := range dirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if appendCertFile(pool, filepath.Join(dir, entry.Name())) {
				appended = true
			}
		}
	}
	return appended
}

func appendCertFile(pool *x509.CertPool, path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return pool.AppendCertsFromPEM(pem)
}

func parseCloudflareTraceIP(body string) (string, error) {
	for _, line := range strings.Split(body, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key == "ip" {
			ip := strings.TrimSpace(val)
			if net.ParseIP(ip).To4() == nil {
				return "", fmt.Errorf("invalid trace IP %q", ip)
			}
			return ip, nil
		}
	}
	return "", fmt.Errorf("trace response has no ip field")
}

func fetchArvanTraceIP() (string, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, networkName, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		TLSClientConfig:       testTLSConfig("arvancloud.ir"),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://arvancloud.ir", nil)
	if err != nil {
		return "", err
	}
	req.Host = "invalid"

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return parseArvanTraceIP(string(body))
}

var arvanIPPattern = regexp.MustCompile(`Your IP:\s*([0-9.]+)`)

func parseArvanTraceIP(body string) (string, error) {
	m := arvanIPPattern.FindStringSubmatch(body)
	if len(m) != 2 {
		return "", fmt.Errorf("response has no internal IP")
	}
	ip := m[1]
	if net.ParseIP(ip).To4() == nil {
		return "", fmt.Errorf("invalid internal IP %q", ip)
	}
	return ip, nil
}

func fetchE2EDNSJSON(listenAddr string) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, networkName, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", listenAddr)
		},
		TLSClientConfig:       testTLSConfig("one.one.one.one"),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://one.one.one.one/dns-query?name=one.one.one.one&type=A", nil)
	if err != nil {
		return err
	}
	req.Header.Set("accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}
	return nil
}

func loopbackListenAddr(listenAddr string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return listenAddr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func loadInitialFileOptions(args []string) (config.FileOptions, string, error) {
	path, provided, err := configPathFromArgs(args)
	if err != nil {
		return config.FileOptions{}, "", err
	}
	if provided {
		opts, err := config.LoadFileOptions(path)
		return opts, path, err
	}
	const defaultPath = "config.ini"
	if _, err := os.Stat(defaultPath); err == nil {
		opts, err := config.LoadFileOptions(defaultPath)
		return opts, defaultPath, err
	} else if !os.IsNotExist(err) {
		return config.FileOptions{}, "", err
	}
	return config.FileOptions{}, "", nil
}

func configPathFromArgs(args []string) (path string, provided bool, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-config" || arg == "--config" {
			if i+1 >= len(args) {
				return "", true, fmt.Errorf("-config requires a path")
			}
			return args[i+1], true, nil
		}
		if strings.HasPrefix(arg, "-config=") {
			return strings.TrimPrefix(arg, "-config="), true, nil
		}
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config="), true, nil
		}
	}
	return "", false, nil
}

func applyOptionDefaults(
	fileOpts config.FileOptions,
	optListen, optConnect, optFakeSNI, optUTLS, injectorMode *string,
	fakeRepeat *int,
	fakeDelay, ackTimeout *time.Duration,
	enableFragment *bool,
	fragmentDelay *time.Duration,
	sniChunk *int,
) {
	*fakeRepeat = 1
	*fakeDelay = 2 * time.Millisecond
	*ackTimeout = 2 * time.Second
	*fragmentDelay = 500 * time.Millisecond
	*sniChunk = packet.DefaultSNIChunkBytes

	if fileOpts.Has("listen") {
		*optListen = fileOpts.Listen
	}
	if fileOpts.Has("connect") {
		*optConnect = fileOpts.Connect
	}
	if fileOpts.Has("fake-sni") {
		*optFakeSNI = fileOpts.FakeSNI
	}
	if fileOpts.Has("fake-repeat") {
		*fakeRepeat = fileOpts.FakeRepeat
	}
	if fileOpts.Has("fake-delay") {
		*fakeDelay = fileOpts.FakeDelay
	}
	if fileOpts.Has("ack-timeout") {
		*ackTimeout = fileOpts.AckTimeout
	}
	if fileOpts.Has("injector") {
		*injectorMode = fileOpts.Injector
	}
	if fileOpts.Has("utls") {
		*optUTLS = fileOpts.UTLS
	}
	if fileOpts.Has("enable-fragment") {
		*enableFragment = fileOpts.EnableFragment
	}
	if fileOpts.Has("fragment-delay") {
		*fragmentDelay = fileOpts.FragmentDelay
	}
	if fileOpts.Has("sni-chunk") {
		*sniChunk = fileOpts.SNIChunk
	}
}

func stopMonitoring(fakeInjector injection.TCPInjector, conn *injection.FakeInjectiveConnection) {
	conn.Mu.Lock()
	conn.Monitor = false
	conn.Mu.Unlock()
	fakeInjector.UnregisterConn(conn)
}

func closePair(a, b net.Conn) {
	a.Close()
	b.Close()
}

func forwardFragmentedClientHello(incoming, outgoing net.Conn, delay time.Duration, sniChunkBytes int, logEachFragment, logSummary bool) error {
	if err := incoming.SetReadDeadline(time.Now().Add(firstClientHelloTimeout)); err != nil {
		return err
	}
	rec, err := packet.ReadFirstTLSRecord(incoming)
	_ = incoming.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	frags := packet.SplitClientHelloRecord(rec, sniChunkBytes)
	if logSummary {
		log.Printf("fragment: %d write(s), sni-chunk=%d, delay=%v", nonEmptyFragments(frags), sniChunkBytes, delay)
	}
	var tcpFrag *net.TCPConn
	if tc, ok := outgoing.(*net.TCPConn); ok {
		tcpFrag = tc
	}
	return packet.WriteClientHelloFragments(outgoing, frags, delay, tcpFrag, logEachFragment)
}

func nonEmptyFragments(frags [][]byte) int {
	n := 0
	for _, frag := range frags {
		if len(frag) > 0 {
			n++
		}
	}
	return n
}

func relay(dst, src net.Conn) {
	const bufSize = 65575
	buf := make([]byte, bufSize)
	_, _ = io.CopyBuffer(dst, src, buf)
}
