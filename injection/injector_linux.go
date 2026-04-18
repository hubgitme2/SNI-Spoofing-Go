//go:build linux

package injection

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
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
	nfqueueNum uint16 = 100
	fwMark     int    = 0x1337

	// Used when NIC MTU is unknown or computed MSS would be invalid.
	fallbackTCPPayloadMax = 1000

	// sysctlNetNFQueueMaxLen is net.netfilter.nf_queue_maxlen (default queue depth for nfqueue).
	sysctlNetNFQueueMaxLen = "/proc/sys/net/netfilter/nf_queue_maxlen"
	// sysctlNetCoreRmemMax is net.core.rmem_max (caps SO_RCVBUF for netlink).
	sysctlNetCoreRmemMax = "/proc/sys/net/core/rmem_max"

	desiredNetlinkRcvBuf = 8 * 1024 * 1024
	// Upper bound in case sysctl returns garbage.
	maxReasonableNFQueueLen = 65536
)

// FakeTcpInjector intercepts TCP packets via nfqueue and injects fake
// TLS ClientHello packets using raw sockets on Linux.
type FakeTcpInjector struct {
	nf          *nfqueue.Nfqueue
	rawFd       int          // raw socket for injecting fake packets
	Connections sync.Map     // map[connection.ConnID]*FakeInjectiveConnection
	interfaceIP string
	connectIP   string
	connectPort uint16
	// nicMTU is the egress interface MTU for interfaceIP (0 = unknown).
	nicMTU int
	ctx    context.Context
	cancel context.CancelFunc
}

// NewFakeTcpInjector creates a new nfqueue-based injector and sets up iptables rules.
func NewFakeTcpInjector(interfaceIP, connectIP string, connectPort uint16) (*FakeTcpInjector, error) {
	ctx, cancel := context.WithCancel(context.Background())

	mtu := nicMTUForLocalIPv4(interfaceIP)
	f := &FakeTcpInjector{
		interfaceIP: interfaceIP,
		connectIP:   connectIP,
		connectPort: connectPort,
		nicMTU:      mtu,
		ctx:         ctx,
		cancel:      cancel,
		rawFd:       -1,
	}
	if mtu > 0 {
		log.Printf("injector: NIC MTU %d for %s", mtu, interfaceIP)
	} else {
		log.Printf("injector: could not resolve NIC MTU for %s, using fallback MSS %d", interfaceIP, fallbackTCPPayloadMax)
	}

	// Create raw socket for injecting fake packets
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}
	// IP_HDRINCL: we provide the full IP header
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	// Mark packets so iptables skips nfqueue for them
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, fwMark)
	// Allow IP fragmentation when DF is cleared (oversized injection datagrams).
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT); err != nil {
		syscall.Close(fd)
		cancel()
		return nil, fmt.Errorf("IP_MTU_DISCOVER: %w", err)
	}
	f.rawFd = fd

	// Set up iptables rules
	if err := f.setupIptables(); err != nil {
		syscall.Close(fd)
		cancel()
		return nil, fmt.Errorf("failed to setup iptables: %w", err)
	}

	// Open nfqueue
	maxQLen := nfqueueMaxQueueLenFromSysctl()
	if maxQLen == 0 {
		log.Printf("injector: nfqueue MaxQueueLen: default (unreadable sysctl %s)", sysctlNetNFQueueMaxLen)
	} else {
		log.Printf("injector: nfqueue MaxQueueLen: %d (from %s)", maxQLen, sysctlNetNFQueueMaxLen)
	}
	cfg := nfqueue.Config{
		NfQueue:      nfqueueNum,
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
	// Larger userspace recv buffer reduces "recvmsg: no buffer space available"
	// when the kernel delivers nfqueue packets faster than we issue verdicts.
	rcv := netlinkRecvBufFromSysctl()
	if err := nf.Con.SetReadBuffer(rcv); err != nil {
		log.Printf("injector: nfqueue SetReadBuffer(%d): %v (continuing with default)", rcv, err)
	} else if rcv < desiredNetlinkRcvBuf {
		log.Printf("injector: nfqueue recv buffer %d bytes (capped by %s; raise net.core.rmem_max for up to %d)",
			rcv, sysctlNetCoreRmemMax, desiredNetlinkRcvBuf)
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

// nicMTUForLocalIPv4 returns the MTU of the interface that owns localIPv4, or 0.
func nicMTUForLocalIPv4(localIPv4 string) int {
	ip := net.ParseIP(localIPv4)
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var cand net.IP
			switch v := a.(type) {
			case *net.IPNet:
				cand = v.IP
			case *net.IPAddr:
				cand = v.IP
			default:
				continue
			}
			cand = cand.To4()
			if cand == nil || !cand.Equal(ip4) {
				continue
			}
			return iface.MTU
		}
	}
	return 0
}

// segmentMSS returns max TCP payload bytes per injected packet from NIC MTU and template IPv4/TCP headers.
func segmentMSS(nicMTU int, template []byte) int {
	if nicMTU <= 0 || packet.IPVersion(template) != 4 {
		return fallbackTCPPayloadMax
	}
	ipLen := packet.IPHeaderLen(template)
	tcpLen := packet.TCPDataOffset(template)
	if ipLen < 20 || tcpLen < 20 {
		return fallbackTCPPayloadMax
	}
	overhead := ipLen + tcpLen
	if nicMTU <= overhead {
		return fallbackTCPPayloadMax
	}
	mss := nicMTU - overhead
	if mss < 128 {
		return fallbackTCPPayloadMax
	}
	return mss
}

// setupIptables adds iptables rules to redirect relevant TCP packets to nfqueue.
func (f *FakeTcpInjector) setupIptables() error {
	port := fmt.Sprintf("%d", f.connectPort)
	mark := fmt.Sprintf("0x%x", fwMark)
	queueNum := fmt.Sprintf("%d", nfqueueNum)

	// OUTPUT: outbound packets to target (skip packets with our fwmark)
	if err := runCmd("iptables", "-I", "OUTPUT", "-p", "tcp",
		"-d", f.connectIP, "--dport", port,
		"-m", "mark", "!", "--mark", mark,
		"-j", "NFQUEUE", "--queue-num", queueNum); err != nil {
		return fmt.Errorf("iptables OUTPUT rule: %w", err)
	}

	// INPUT: inbound packets from target
	if err := runCmd("iptables", "-I", "INPUT", "-p", "tcp",
		"-s", f.connectIP, "--sport", port,
		"-j", "NFQUEUE", "--queue-num", queueNum); err != nil {
		// Cleanup the OUTPUT rule we just added
		runCmd("iptables", "-D", "OUTPUT", "-p", "tcp",
			"-d", f.connectIP, "--dport", port,
			"-m", "mark", "!", "--mark", mark,
			"-j", "NFQUEUE", "--queue-num", queueNum)
		return fmt.Errorf("iptables INPUT rule: %w", err)
	}

	log.Printf("iptables rules set up (queue %s, mark %s)", queueNum, mark)
	return nil
}

// cleanupIptables removes the iptables rules.
func (f *FakeTcpInjector) cleanupIptables() {
	port := fmt.Sprintf("%d", f.connectPort)
	mark := fmt.Sprintf("0x%x", fwMark)
	queueNum := fmt.Sprintf("%d", nfqueueNum)

	runCmd("iptables", "-D", "OUTPUT", "-p", "tcp",
		"-d", f.connectIP, "--dport", port,
		"-m", "mark", "!", "--mark", mark,
		"-j", "NFQUEUE", "--queue-num", queueNum)

	runCmd("iptables", "-D", "INPUT", "-p", "tcp",
		"-s", f.connectIP, "--sport", port,
		"-j", "NFQUEUE", "--queue-num", queueNum)

	log.Println("iptables rules cleaned up")
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s: %w", name, args, string(output), err)
	}
	return nil
}

// Start runs the nfqueue packet processing loop (blocks until context is cancelled).
func (f *FakeTcpInjector) Start() {
	err := f.nf.RegisterWithErrorFunc(f.ctx,
		func(a nfqueue.Attribute) int {
			f.processPacket(a)
			return 0
		},
		func(e error) int {
			log.Printf("nfqueue error: %v", e)
			return 0
		},
	)
	if err != nil {
		log.Printf("nfqueue register error: %v", err)
		return
	}
	<-f.ctx.Done()
}

// Close stops the injector and cleans up iptables rules.
func (f *FakeTcpInjector) Close() {
	f.cancel()
	if f.nf != nil {
		f.nf.Close()
	}
	if f.rawFd >= 0 {
		syscall.Close(f.rawFd)
		f.rawFd = -1
	}
	f.cleanupIptables()
}

// sendRawPacket sends a raw IP packet bypassing nfqueue (due to SO_MARK).
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

// processPacket handles a single nfqueue packet.
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

	// IPv4 only: do not interpret IPv6 (or non-IP) payloads as IPv4.
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

	// Determine direction: if srcIP == our interface IP, it's outbound
	isOutbound := srcIP == f.interfaceIP

	if isOutbound {
		cID := connection.ConnID{SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort}
		val, ok := f.Connections.Load(cID)
		if !ok {
			f.nf.SetVerdict(id, nfqueue.NfAccept)
			return
		}
		conn := val.(*FakeInjectiveConnection)
		conn.Mu.Lock()
		defer conn.Mu.Unlock()
		if !conn.Monitor {
			f.nf.SetVerdict(id, nfqueue.NfAccept)
			return
		}
		f.onOutboundPacket(id, payload, conn)
	} else {
		// Inbound: key is reversed (dst=us, src=remote)
		cID := connection.ConnID{SrcIP: dstIP, SrcPort: dstPort, DstIP: srcIP, DstPort: srcPort}
		val, ok := f.Connections.Load(cID)
		if !ok {
			f.nf.SetVerdict(id, nfqueue.NfAccept)
			return
		}
		conn := val.(*FakeInjectiveConnection)
		conn.Mu.Lock()
		defer conn.Mu.Unlock()
		if !conn.Monitor {
			f.nf.SetVerdict(id, nfqueue.NfAccept)
			return
		}
		f.onInboundPacket(id, payload, conn)
	}
}

// onUnexpectedPacket handles unexpected packets.
func (f *FakeTcpInjector) onUnexpectedPacket(id uint32, raw []byte, conn *FakeInjectiveConnection, info string) {
	fmt.Println(info, packet.PacketSummary(raw))
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

// onInboundPacket processes packets arriving from the remote server.
func (f *FakeTcpInjector) onInboundPacket(id uint32, raw []byte, conn *FakeInjectiveConnection) {
	if conn.SynSeq == -1 {
		f.onUnexpectedPacket(id, raw, conn, "unexpected inbound packet, no syn sent!")
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	// SYN-ACK from server
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

	// Pure ACK after fake data sent
	if flags.ACK && !flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 && conn.FakeSent {
		expectedSeq := uint32((uint32(conn.SynAckSeq) + 1) & 0xffffffff)
		if conn.SynAckSeq == -1 || expectedSeq != seqNum {
			f.onUnexpectedPacket(id, raw, conn,
				fmt.Sprintf("unexpected inbound ack, seq not matched! %d %d", seqNum, conn.SynAckSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if ackNum != expectedAck {
			f.onUnexpectedPacket(id, raw, conn,
				fmt.Sprintf("unexpected inbound ack, ack not matched! %d %d", ackNum, conn.SynSeq))
			return
		}
		conn.Monitor = false
		// Accept this packet so the kernel TCP stack sees it
		f.nf.SetVerdict(id, nfqueue.NfAccept)
		select {
		case conn.T2aChan <- "fake_data_ack_recv":
		default:
		}
		return
	}

	f.onUnexpectedPacket(id, raw, conn, "unexpected inbound packet")
}

// onOutboundPacket processes packets going to the remote server.
func (f *FakeTcpInjector) onOutboundPacket(id uint32, raw []byte, conn *FakeInjectiveConnection) {
	if conn.SchFakeSent {
		f.onUnexpectedPacket(id, raw, conn, "unexpected outbound packet after fake sent!")
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	// SYN packet
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

	// ACK packet completing handshake
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
		// Accept the ACK first
		f.nf.SetVerdict(id, nfqueue.NfAccept)
		conn.SchFakeSent = true

		// Clone raw bytes for the injection goroutine
		rawCopy := make([]byte, len(raw))
		copy(rawCopy, raw)
		go f.fakeSendThread(rawCopy, conn)
		return
	}

	f.onUnexpectedPacket(id, raw, conn, "unexpected outbound packet")
}

// fakeSendThread injects the fake ClientHello via raw socket.
func (f *FakeTcpInjector) fakeSendThread(rawCopy []byte, conn *FakeInjectiveConnection) {
	time.Sleep(1 * time.Millisecond)

	conn.Mu.Lock()
	defer conn.Mu.Unlock()

	if !conn.Monitor {
		return
	}

	if conn.BypassMethod != "wrong_seq" {
		log.Printf("not implemented bypass method: %s", conn.BypassMethod)
		conn.AbortUnexpectedCloseLocked()
		return
	}

	if err := f.injectWrongSeqClientHello(rawCopy, conn); err != nil {
		log.Printf("inject fake ClientHello: %v", err)
		conn.AbortUnexpectedCloseLocked()
		return
	}
	conn.FakeSent = true
}

// injectWrongSeqClientHello sends one or more TCP segments for conn.FakeData using
// wrong-seq semantics. Large TLS ClientHellos are split so each IP packet fits the MTU.
func (f *FakeTcpInjector) injectWrongSeqClientHello(template []byte, conn *FakeInjectiveConnection) error {
	payload := conn.FakeData
	total := len(payload)
	if total == 0 {
		return fmt.Errorf("empty FakeData")
	}

	baseWrongSeq := (uint32(conn.SynSeq) + 1 - uint32(total)) & 0xffffffff
	baseIdent := uint16(0)
	if packet.IPVersion(template) == 4 {
		baseIdent = packet.IPv4Ident(template)
	}

	mss := segmentMSS(f.nicMTU, template)
	chunkIdx := 0
	for off := 0; off < total; off += mss {
		end := off + mss
		if end > total {
			end = total
		}
		chunk := payload[off:end]
		isLast := end == total

		pkt := packet.SetTCPPayload(template, chunk)
		if pkt == nil {
			return fmt.Errorf("SetTCPPayload: invalid TCP/IP packet")
		}
		packet.SetTCPSeqNum(pkt, baseWrongSeq+uint32(off))
		if isLast {
			packet.SetTCPFlag(pkt, "psh", true)
		} else {
			packet.SetTCPFlag(pkt, "psh", false)
		}
		if packet.IPVersion(pkt) == 4 {
			packet.SetIPv4Ident(pkt, (baseIdent+1+uint16(chunkIdx))&0xffff)
			packet.ClearIPv4DontFragment(pkt)
		}
		chunkIdx++

		computeIPChecksum(pkt)
		computeTCPChecksum(pkt)
		if err := f.sendRawPacket(pkt); err != nil {
			return err
		}
	}
	return nil
}

// computeIPChecksum calculates and sets the IPv4 header checksum.
func computeIPChecksum(raw []byte) {
	ipHdrLen := packet.IPHeaderLen(raw)
	if ipHdrLen < 20 || len(raw) < ipHdrLen {
		return
	}
	// Zero out existing checksum
	raw[10] = 0
	raw[11] = 0
	sum := checksumData(raw[:ipHdrLen])
	binary.BigEndian.PutUint16(raw[10:12], sum)
}

// computeTCPChecksum calculates and sets the TCP checksum using the pseudo-header.
func computeTCPChecksum(raw []byte) {
	ipHdrLen := packet.IPHeaderLen(raw)
	if ipHdrLen < 20 || len(raw) < ipHdrLen+20 {
		return
	}
	srcIP := net.IP(raw[12:16]).To4()
	dstIP := net.IP(raw[16:20]).To4()
	if srcIP == nil || dstIP == nil {
		return
	}
	tcpSegment := raw[ipHdrLen:]
	if len(tcpSegment) < 20 {
		return
	}
	tcpLen := len(tcpSegment)

	// Zero out existing TCP checksum (at offset 16-17 of TCP header)
	tcpSegment[16] = 0
	tcpSegment[17] = 0

	// Build pseudo-header: srcIP(4) + dstIP(4) + zero(1) + proto(1) + tcpLen(2)
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[8] = 0
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))

	data := make([]byte, 0, len(pseudo)+tcpLen)
	data = append(data, pseudo...)
	data = append(data, tcpSegment...)

	sum := checksumData(data)
	binary.BigEndian.PutUint16(tcpSegment[16:18], sum)
}

// checksumData computes the internet checksum (RFC 1071).
func checksumData(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
