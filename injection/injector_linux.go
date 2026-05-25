//go:build linux

package injection

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"

	"sni-spoofing-go/connection"
	"sni-spoofing-go/packet"
)

const (
	sysctlNetNFQueueMaxLen = "/proc/sys/net/netfilter/nf_queue_maxlen"
	sysctlNetCoreRmemMax   = "/proc/sys/net/core/rmem_max"

	desiredNetlinkRcvBuf    = 8 * 1024 * 1024
	maxReasonableNFQueueLen = 65536
)

func randomNFQueueID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func randomFwMark() (int, error) {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		m := int(binary.BigEndian.Uint32(b[:]))
		if m != 0 {
			return m, nil
		}
	}
}

type FakeTcpInjector struct {
	nf          *nfqueue.Nfqueue
	rawFd       int
	Connections sync.Map
	// byLocalPort indexes flows by ephemeral local port when the IPv4 SrcIP on the wire
	// does not match ConnID.SrcIP (e.g. route-chosen address vs -interface IP).
	byLocalPort     sync.Map // uint16 -> *FakeInjectiveConnection
	connectIP       string
	connectPort     uint16
	nicMTU          int
	nfqueueNum      uint16
	fwMark          int
	ctx             context.Context
	cancel          context.CancelFunc
	injectorReady   chan struct{}
	injectorOpenErr error
	closeOnce       sync.Once
}

func NewFakeTcpInjector(interfaceIP string, connectIPv4s []string, connectPort uint16) (*FakeTcpInjector, error) {
	if len(connectIPv4s) == 0 {
		return nil, fmt.Errorf("no upstream IPv4 addresses")
	}
	connectIP := connectIPv4s[0]

	ctx, cancel := context.WithCancel(context.Background())

	qid, err := randomNFQueueID()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("nfqueue queue id: %w", err)
	}
	mark, err := randomFwMark()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("fw mark: %w", err)
	}

	mtu := nicMTUForLocalIPv4(interfaceIP)
	f := &FakeTcpInjector{
		connectIP:     connectIP,
		connectPort:   connectPort,
		nicMTU:        mtu,
		nfqueueNum:    qid,
		fwMark:        mark,
		ctx:           ctx,
		cancel:        cancel,
		rawFd:         -1,
		injectorReady: make(chan struct{}),
	}
	if mtu == 0 {
		log.Printf("injector: fallback MSS %d", fallbackTCPPayloadMax)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		cancel()
		return nil, fmt.Errorf("IP_HDRINCL: %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, f.fwMark); err != nil {
		syscall.Close(fd)
		cancel()
		return nil, fmt.Errorf("SO_MARK: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT); err != nil {
		syscall.Close(fd)
		cancel()
		return nil, fmt.Errorf("IP_MTU_DISCOVER: %w", err)
	}
	f.rawFd = fd

	if err := f.setupIptables(); err != nil {
		syscall.Close(fd)
		cancel()
		return nil, fmt.Errorf("failed to setup iptables: %w", err)
	}

	maxQLen := nfqueueMaxQueueLenFromSysctl()
	if maxQLen > 0 {
		log.Printf("nfqueue: max queue %d", maxQLen)
	}
	cfg := nfqueue.Config{
		NfQueue:      f.nfqueueNum,
		MaxPacketLen: maxIPv4DatagramLen(),
		MaxQueueLen:  maxQLen,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}
	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		f.cleanupIptables()
		syscall.Close(fd)
		cancel()
		return nil, fmt.Errorf("failed to open nfqueue: %w", err)
	}
	rcv := netlinkRecvBufFromSysctl()
	if err := nf.Con.SetReadBuffer(rcv); err != nil {
		log.Printf("nfqueue: recv buffer unchanged: %v", err)
	} else if rcv < desiredNetlinkRcvBuf {
		log.Printf("nfqueue: recv buffer %d", rcv)
	}
	f.nf = nf

	return f, nil
}

// sysctlUint32 reads a single positive decimal integer from a /proc/sys path.
func sysctlUint32(path string) (uint32, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil || v == 0 {
		return 0, false
	}
	return uint32(v), true
}

// nfqueueMaxQueueLenFromSysctl returns net.netfilter.nf_queue_maxlen for nfqueue.Config,
// or 0 so go-nfqueue uses its built-in default (1024) when the sysctl is missing or invalid.
func nfqueueMaxQueueLenFromSysctl() uint32 {
	v, ok := sysctlUint32(sysctlNetNFQueueMaxLen)
	if !ok {
		return 0
	}
	if v > maxReasonableNFQueueLen {
		return maxReasonableNFQueueLen
	}
	return v
}

// maxIPv4DatagramLen is the maximum IPv4 total length (16-bit length field). NFQUEUE copy
// length is not exposed as a separate sysctl; this matches the protocol maximum.
func maxIPv4DatagramLen() uint32 {
	return 0xFFFF
}

// netlinkRecvBufFromSysctl returns a recv buffer size capped by net.core.rmem_max so
// SetReadBuffer is less likely to fail on strict sysctl defaults.
func netlinkRecvBufFromSysctl() int {
	max, ok := sysctlUint32(sysctlNetCoreRmemMax)
	if !ok {
		return desiredNetlinkRcvBuf
	}
	if int(max) < desiredNetlinkRcvBuf {
		return int(max)
	}
	return desiredNetlinkRcvBuf
}

func (f *FakeTcpInjector) setupIptables() error {
	port := fmt.Sprintf("%d", f.connectPort)
	mark := fmt.Sprintf("0x%x", f.fwMark)
	queueNum := fmt.Sprintf("%d", f.nfqueueNum)

	if err := runCmd("iptables", "-I", "OUTPUT", "-p", "tcp",
		"-d", f.connectIP, "--dport", port,
		"-m", "mark", "!", "--mark", mark,
		"-j", "NFQUEUE", "--queue-num", queueNum); err != nil {
		return fmt.Errorf("iptables OUTPUT rule: %w", err)
	}

	if err := runCmd("iptables", "-I", "INPUT", "-p", "tcp",
		"-s", f.connectIP, "--sport", port,
		"-j", "NFQUEUE", "--queue-num", queueNum); err != nil {
		runCmd("iptables", "-D", "OUTPUT", "-p", "tcp",
			"-d", f.connectIP, "--dport", port,
			"-m", "mark", "!", "--mark", mark,
			"-j", "NFQUEUE", "--queue-num", queueNum)
		return fmt.Errorf("iptables INPUT rule: %w", err)
	}

	log.Printf("iptables: ready queue=%s mark=%s", queueNum, mark)
	return nil
}

func (f *FakeTcpInjector) cleanupIptables() {
	port := fmt.Sprintf("%d", f.connectPort)
	mark := fmt.Sprintf("0x%x", f.fwMark)
	queueNum := fmt.Sprintf("%d", f.nfqueueNum)

	runCmd("iptables", "-D", "OUTPUT", "-p", "tcp",
		"-d", f.connectIP, "--dport", port,
		"-m", "mark", "!", "--mark", mark,
		"-j", "NFQUEUE", "--queue-num", queueNum)

	runCmd("iptables", "-D", "INPUT", "-p", "tcp",
		"-s", f.connectIP, "--sport", port,
		"-j", "NFQUEUE", "--queue-num", queueNum)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s: %w", name, args, string(output), err)
	}
	return nil
}

func (f *FakeTcpInjector) Start() error {
	err := f.nf.RegisterWithErrorFunc(f.ctx,
		func(a nfqueue.Attribute) int {
			f.processPacket(a)
			return 0
		},
		func(e error) int {
			if f.ctx.Err() == nil {
				log.Printf("nfqueue error: %v", e)
			}
			return 0
		},
	)
	if err != nil {
		log.Printf("nfqueue register error: %v", err)
		f.injectorOpenErr = err
		close(f.injectorReady)
		return nil
	}
	close(f.injectorReady)
	<-f.ctx.Done()
	return nil
}

func (f *FakeTcpInjector) WaitInjectorReady() error {
	<-f.injectorReady
	return f.injectorOpenErr
}

func (f *FakeTcpInjector) Close() {
	f.closeOnce.Do(func() {
		f.cancel()
		if f.nf != nil {
			f.nf.Close()
		}
		if f.rawFd >= 0 {
			syscall.Close(f.rawFd)
			f.rawFd = -1
		}
		f.cleanupIptables()
	})
}

func (f *FakeTcpInjector) sendRawPacket(rawIP []byte) error {
	dstIP := packet.IPv4DstAddr(rawIP)
	if dstIP == nil {
		return fmt.Errorf("raw packet has no IPv4 destination")
	}
	ip4 := dstIP.To4()
	if ip4 == nil {
		return fmt.Errorf("raw packet destination is not IPv4")
	}
	sa := &syscall.SockaddrInet4{Port: 0}
	copy(sa.Addr[:], ip4)
	return syscall.Sendto(f.rawFd, rawIP, 0, sa)
}

func (f *FakeTcpInjector) processPacket(a nfqueue.Attribute) {
	if a.PacketID == nil {
		log.Printf("nfqueue: missing packet id (cannot issue verdict)")
		return
	}
	id := *a.PacketID
	if a.Payload == nil {
		if err := f.nf.SetVerdict(id, nfqueue.NfAccept); err != nil {
			log.Printf("nfqueue SetVerdict: %v", err)
		}
		return
	}
	payload := *a.Payload // raw IP packet

	if len(payload) < 40 {
		f.nf.SetVerdict(id, nfqueue.NfAccept)
		return
	}

	if packet.IPVersion(payload) != 4 {
		if err := f.nf.SetVerdict(id, nfqueue.NfAccept); err != nil {
			log.Printf("nfqueue SetVerdict: %v", err)
		}
		return
	}

	srcIP := packet.IPv4SrcAddr(payload).String()
	dstIP := packet.IPv4DstAddr(payload).String()
	srcPort := packet.TCPSrcPort(payload)
	dstPort := packet.TCPDstPort(payload)

	conn, outbound, ok := f.lookupConnQuad(srcIP, srcPort, dstIP, dstPort)
	if !ok {
		f.nf.SetVerdict(id, nfqueue.NfAccept)
		return
	}
	c := conn
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if !c.Monitor {
		f.nf.SetVerdict(id, nfqueue.NfAccept)
		return
	}
	if outbound {
		f.onOutboundPacket(id, payload, c)
	} else {
		f.onInboundPacket(id, payload, c)
	}
}

func (f *FakeTcpInjector) lookupConnQuad(srcIP string, srcPort uint16, dstIP string, dstPort uint16) (conn *FakeInjectiveConnection, outbound bool, ok bool) {
	idOut := connection.ConnID{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort}
	if v, ok := f.Connections.Load(idOut); ok {
		return v.(*FakeInjectiveConnection), true, true
	}
	idIn := connection.ConnID{SrcIP: dstIP, SrcPort: dstPort, DstIP: srcIP, DstPort: srcPort}
	if v, ok := f.Connections.Load(idIn); ok {
		return v.(*FakeInjectiveConnection), false, true
	}
	if v, ok := f.byLocalPort.Load(srcPort); ok {
		c := v.(*FakeInjectiveConnection)
		if ipv4Equal(dstIP, c.DstIP) && dstPort == c.DstPort {
			return c, true, true
		}
	}
	if v, ok := f.byLocalPort.Load(dstPort); ok {
		c := v.(*FakeInjectiveConnection)
		if ipv4Equal(srcIP, c.DstIP) && srcPort == c.DstPort {
			return c, false, true
		}
	}
	return nil, false, false
}

func (f *FakeTcpInjector) onUnexpectedPacket(id uint32, raw []byte, conn *FakeInjectiveConnection, info string) {
	log.Printf("injector: %s %s", info, packet.PacketSummary(raw))
	if conn.Sock != nil {
		conn.Sock.Close()
	}
	if conn.PeerSock != nil {
		conn.PeerSock.Close()
	}
	conn.Monitor = false
	select {
	case conn.T2aChan <- "unexpected_close":
	default:
	}
	f.nf.SetVerdict(id, nfqueue.NfAccept)
}

func (f *FakeTcpInjector) onInboundPacket(id uint32, raw []byte, conn *FakeInjectiveConnection) {
	if conn.SynSeq == -1 {
		f.onUnexpectedPacket(id, raw, conn, "unexpected inbound packet, no syn sent!")
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.ACK && flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		if conn.SynAckSeq != -1 && conn.SynAckSeq != int64(seqNum) {
			f.onUnexpectedPacket(id, raw, conn,
				fmt.Sprintf("unexpected inbound syn-ack, seq change! %d %d", seqNum, conn.SynAckSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if ackNum != expectedAck {
			f.onUnexpectedPacket(id, raw, conn,
				fmt.Sprintf("unexpected inbound syn-ack, ack not matched! %d %d", ackNum, conn.SynSeq))
			return
		}
		conn.SynAckSeq = int64(seqNum)
		f.nf.SetVerdict(id, nfqueue.NfAccept)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && conn.FakeInjectInProgress.Load() && !conn.FakeSent.Load() {
		conn.PostFakeAckObserved.Store(true)
		f.nf.SetVerdict(id, nfqueue.NfAccept)
		return
	}

	// CDNs differ on seq/ack fields after the wrong-seq fake; accept a strict match or a peer ACK.
	if flags.ACK && !flags.SYN && !flags.RST && conn.FakeSent.Load() && conn.SynAckSeq != -1 {
		strict := postFakeInboundStrictOK(seqNum, ackNum, conn)
		if !strict && !postFakeInboundPermissiveOK(flags) {
			f.onUnexpectedPacket(id, raw, conn,
				fmt.Sprintf("unexpected inbound after fake seq=%d ack=%d synAck=%d syn=%d strict=%v", seqNum, ackNum, conn.SynAckSeq, conn.SynSeq, strict))
			return
		}
		conn.Monitor = false
		f.nf.SetVerdict(id, nfqueue.NfAccept)
		select {
		case conn.T2aChan <- "fake_data_ack_recv":
		default:
		}
		return
	}

	f.onUnexpectedPacket(id, raw, conn, "unexpected inbound packet")
}

func (f *FakeTcpInjector) onOutboundPacket(id uint32, raw []byte, conn *FakeInjectiveConnection) {
	if conn.FakeSent.Load() {
		f.nf.SetVerdict(id, nfqueue.NfAccept)
		return
	}
	if conn.FakeInjectInProgress.Load() {
		f.nf.SetVerdict(id, nfqueue.NfAccept)
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.SYN && !flags.ACK && !flags.RST && !flags.FIN && payloadLen == 0 {
		if ackNum != 0 {
			f.onUnexpectedPacket(id, raw, conn, "unexpected outbound syn, ack_num is not zero!")
			return
		}
		if conn.SynSeq != -1 && conn.SynSeq != int64(seqNum) {
			f.onUnexpectedPacket(id, raw, conn,
				fmt.Sprintf("unexpected outbound syn, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		conn.SynSeq = int64(seqNum)
		f.nf.SetVerdict(id, nfqueue.NfAccept)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		expectedSeq := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if conn.SynSeq == -1 || expectedSeq != seqNum {
			f.onUnexpectedPacket(id, raw, conn,
				fmt.Sprintf("unexpected outbound ack, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynAckSeq) + 1) & 0xffffffff)
		if conn.SynAckSeq == -1 || ackNum != expectedAck {
			f.onUnexpectedPacket(id, raw, conn,
				fmt.Sprintf("unexpected outbound ack, ack not matched! %d %d", ackNum, conn.SynAckSeq))
			return
		}
		// Accept the ACK first, then inject off the nfqueue callback (same idea as Windows async injection).
		f.nf.SetVerdict(id, nfqueue.NfAccept)

		rawCopy := make([]byte, len(raw))
		copy(rawCopy, raw)
		conn.FakeInjectInProgress.Store(true)
		go f.runFakeInjectionLocked(rawCopy, conn)
		return
	}

	f.onUnexpectedPacket(id, raw, conn, "unexpected outbound packet")
}

// runFakeInjectionLocked injects the fake ClientHello via raw socket on a dedicated goroutine.
// It does not hold conn.Mu during inject/sleep so nfqueue can still process inbound ACKs (FakeInjectInProgress path).
func (f *FakeTcpInjector) runFakeInjectionLocked(rawCopy []byte, conn *FakeInjectiveConnection) {
	defer conn.FakeInjectInProgress.Store(false)

	time.Sleep(1 * time.Millisecond)

	conn.Mu.Lock()
	if !conn.Monitor {
		conn.Mu.Unlock()
		return
	}
	if conn.BypassMethod != "wrong_seq" {
		log.Printf("not implemented bypass method: %s", conn.BypassMethod)
		conn.AbortUnexpectedCloseLocked()
		conn.Mu.Unlock()
		return
	}
	conn.Mu.Unlock()

	repeat := conn.FakeRepeat
	if repeat < 1 {
		repeat = 1
	}
	total := len(conn.FakeData)
	mss := segmentMSS(f.nicMTU, rawCopy)
	segPerInject := (total + mss - 1) / mss
	if segPerInject < 1 {
		segPerInject = 1
	}
	for i := 0; i < repeat; i++ {
		if !conn.IsMonitoring() {
			return
		}
		if err := injectWrongSeqClientHello(f.nicMTU, rawCopy, conn, conn.IsMonitoring, f.sendRawPacket); err != nil {
			if err == errInjectionCanceled {
				return
			}
			log.Printf("inject fake ClientHello: %v", err)
			conn.Mu.Lock()
			conn.AbortUnexpectedCloseLocked()
			conn.Mu.Unlock()
			return
		}
		log.Printf("injector: fake ClientHello sent (%d/%d, %d bytes, %d segment(s))",
			i+1, repeat, total, segPerInject)
		if i+1 < repeat && conn.FakeDelay > 0 && !sleepWhileContinue(conn.FakeDelay, conn.IsMonitoring) {
			return
		}
	}
	conn.FakeSent.Store(true)
	if conn.PostFakeAckObserved.Load() {
		conn.Mu.Lock()
		if conn.Monitor {
			conn.Monitor = false
			select {
			case conn.T2aChan <- "fake_data_ack_recv":
			default:
			}
		}
		conn.Mu.Unlock()
	}
}

func (f *FakeTcpInjector) RegisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Store(conn.ID, conn)
	f.byLocalPort.Store(conn.SrcPort, conn)
}

func (f *FakeTcpInjector) UnregisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Delete(conn.ID)
	f.byLocalPort.Delete(conn.SrcPort)
}
