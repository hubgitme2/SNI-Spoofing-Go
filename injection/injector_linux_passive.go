//go:build linux

package injection

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"sni-spoofing-go/connection"
	"sni-spoofing-go/packet"
)

const ethernetHeaderLen = 14

type passiveFakeTcpInjector struct {
	fd      int
	ifindex int

	linkHdr   []byte
	linkHdrMu sync.RWMutex

	Connections sync.Map
	byLocalPort sync.Map
	localIP     string
	connectIP   string
	connectPort uint16
	nicMTU      int

	ctx    context.Context
	cancel context.CancelFunc

	injectorReady chan struct{}
	closeOnce     sync.Once
	sendMu        sync.Mutex
}

func newPassiveFakeTcpInjector(interfaceIP string, connectIPv4s []string, connectPort uint16) (TCPInjector, error) {
	if len(connectIPv4s) == 0 {
		return nil, fmt.Errorf("no upstream IPv4 addresses")
	}
	iface, err := interfaceByIPv4(interfaceIP)
	if err != nil {
		return nil, err
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}
	cleanup := func(e error) (TCPInjector, error) {
		_ = unix.Close(fd)
		return nil, e
	}

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}); err != nil {
		return cleanup(fmt.Errorf("bind AF_PACKET %s: %w", iface.Name, err))
	}
	if len(iface.HardwareAddr) != 6 {
		return cleanup(fmt.Errorf("passive Linux injector supports Ethernet-like interfaces only; %s has hardware address length %d", iface.Name, len(iface.HardwareAddr)))
	}

	tv := unix.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	if err := attachPassiveHostFilter(fd, connectIPv4s[0]); err != nil {
		log.Printf("passive: filter not installed (%v); filtering in userspace", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	mtu := nicMTUForLocalIPv4(interfaceIP)
	if mtu == 0 {
		log.Printf("injector: fallback MSS %d", fallbackTCPPayloadMax)
	}
	log.Printf("passive: AF_PACKET iface=%s mtu=%d", iface.Name, mtu)

	return &passiveFakeTcpInjector{
		fd:            fd,
		ifindex:       iface.Index,
		localIP:       interfaceIP,
		connectIP:     connectIPv4s[0],
		connectPort:   connectPort,
		nicMTU:        mtu,
		ctx:           ctx,
		cancel:        cancel,
		injectorReady: make(chan struct{}),
	}, nil
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

func interfaceByIPv4(localIPv4 string) (*net.Interface, error) {
	ip := net.ParseIP(localIPv4).To4()
	if ip == nil {
		return nil, fmt.Errorf("local address is not IPv4: %q", localIPv4)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
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
			}
			if cand.To4() != nil && cand.Equal(ip) {
				return &ifaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no interface found for local IPv4 %q", localIPv4)
}

func (f *passiveFakeTcpInjector) Start() error {
	close(f.injectorReady)
	buf := make([]byte, 65536)
	for {
		if f.ctx.Err() != nil {
			return nil
		}
		n, _, err := unix.Recvfrom(f.fd, buf, 0)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			if f.ctx.Err() != nil {
				return nil
			}
			log.Printf("passive recv: %v", err)
			continue
		}
		if n <= 0 {
			continue
		}
		f.onFrame(buf[:n])
	}
}

func (f *passiveFakeTcpInjector) WaitInjectorReady() error {
	<-f.injectorReady
	return nil
}

func (f *passiveFakeTcpInjector) Close() {
	f.closeOnce.Do(func() {
		f.cancel()
		if f.fd >= 0 {
			_ = unix.Close(f.fd)
			f.fd = -1
		}
	})
}

func (f *passiveFakeTcpInjector) RegisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Store(conn.ID, conn)
	f.byLocalPort.Store(conn.SrcPort, conn)
}

func (f *passiveFakeTcpInjector) UnregisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Delete(conn.ID)
	f.byLocalPort.Delete(conn.SrcPort)
}

func (f *passiveFakeTcpInjector) onFrame(frame []byte) {
	if len(frame) < ethernetHeaderLen+40 {
		return
	}
	if frame[12] != 0x08 || frame[13] != 0x00 {
		return
	}
	raw := frame[ethernetHeaderLen:]
	if packet.IPVersion(raw) != 4 {
		return
	}

	src := packet.IPv4SrcAddr(raw)
	dst := packet.IPv4DstAddr(raw)
	if src == nil || dst == nil {
		return
	}
	srcIP := src.String()
	dstIP := dst.String()
	srcPort := packet.TCPSrcPort(raw)
	dstPort := packet.TCPDstPort(raw)

	conn, outbound, ok := f.lookupConnQuad(srcIP, srcPort, dstIP, dstPort)
	if !ok {
		return
	}
	if outbound {
		f.captureLinkHeader(frame)
	}

	conn.Mu.Lock()
	defer conn.Mu.Unlock()
	if !conn.Monitor {
		return
	}
	if outbound {
		f.onOutboundPacket(raw, conn)
	} else {
		f.onInboundPacket(raw, conn)
	}
}

func attachPassiveHostFilter(fd int, connectIP string) error {
	ip := net.ParseIP(connectIP).To4()
	if ip == nil {
		return fmt.Errorf("connect IP is not IPv4: %q", connectIP)
	}
	host := binary.BigEndian.Uint32(ip)
	const accept = 0x40000
	filter := []syscall.SockFilter{
		{Code: 0x28, K: 12},            // ldh [12] EtherType
		{Code: 0x15, Jf: 7, K: 0x0800}, // IPv4
		{Code: 0x30, K: 23},            // ldb [23] protocol
		{Code: 0x15, Jf: 5, K: 6},      // TCP
		{Code: 0x20, K: 26},            // ldw [26] src IPv4
		{Code: 0x15, Jt: 2, K: host},   // src == host -> accept
		{Code: 0x20, K: 30},            // ldw [30] dst IPv4
		{Code: 0x15, Jf: 1, K: host},   // dst == host -> accept
		{Code: 0x06, K: accept},        // accept
		{Code: 0x06, K: 0},             // drop
	}
	return syscall.AttachLsf(fd, filter)
}

func (f *passiveFakeTcpInjector) captureLinkHeader(frame []byte) {
	f.linkHdrMu.RLock()
	have := f.linkHdr != nil
	f.linkHdrMu.RUnlock()
	if have {
		return
	}
	hdr := make([]byte, ethernetHeaderLen)
	copy(hdr, frame[:ethernetHeaderLen])
	f.linkHdrMu.Lock()
	if f.linkHdr == nil {
		f.linkHdr = hdr
	}
	f.linkHdrMu.Unlock()
}

func (f *passiveFakeTcpInjector) lookupConnQuad(srcIP string, srcPort uint16, dstIP string, dstPort uint16) (conn *FakeInjectiveConnection, outbound bool, ok bool) {
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

func (f *passiveFakeTcpInjector) onUnexpectedPacket(raw []byte, conn *FakeInjectiveConnection, info string) {
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
}

func (f *passiveFakeTcpInjector) onInboundPacket(raw []byte, conn *FakeInjectiveConnection) {
	if conn.SynSeq == -1 {
		f.onUnexpectedPacket(raw, conn, "unexpected inbound packet, no syn sent!")
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.ACK && flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		if conn.SynAckSeq != -1 && conn.SynAckSeq != int64(seqNum) {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected inbound syn-ack, seq change! %d %d", seqNum, conn.SynAckSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if ackNum != expectedAck {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected inbound syn-ack, ack not matched! %d %d", ackNum, conn.SynSeq))
			return
		}
		conn.SynAckSeq = int64(seqNum)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && conn.FakeInjectInProgress.Load() && !conn.FakeSent.Load() {
		conn.PostFakeAckObserved.Store(true)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && conn.FakeSent.Load() && conn.SynAckSeq != -1 {
		strict := postFakeInboundStrictOK(seqNum, ackNum, conn)
		if !strict && !postFakeInboundPermissiveOK(flags) {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected inbound after fake seq=%d ack=%d synAck=%d syn=%d strict=%v", seqNum, ackNum, conn.SynAckSeq, conn.SynSeq, strict))
			return
		}
		conn.Monitor = false
		select {
		case conn.T2aChan <- "fake_data_ack_recv":
		default:
		}
		return
	}

	f.onUnexpectedPacket(raw, conn, "unexpected inbound packet")
}

func (f *passiveFakeTcpInjector) onOutboundPacket(raw []byte, conn *FakeInjectiveConnection) {
	if conn.FakeSent.Load() || conn.FakeInjectInProgress.Load() {
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.SYN && !flags.ACK && !flags.RST && !flags.FIN && payloadLen == 0 {
		if ackNum != 0 {
			f.onUnexpectedPacket(raw, conn, "unexpected outbound syn, ack_num is not zero!")
			return
		}
		if conn.SynSeq != -1 && conn.SynSeq != int64(seqNum) {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected outbound syn, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		conn.SynSeq = int64(seqNum)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		expectedSeq := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if conn.SynSeq == -1 || expectedSeq != seqNum {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected outbound ack, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynAckSeq) + 1) & 0xffffffff)
		if conn.SynAckSeq == -1 || ackNum != expectedAck {
			f.onUnexpectedPacket(raw, conn, fmt.Sprintf("unexpected outbound ack, ack not matched! %d %d", ackNum, conn.SynAckSeq))
			return
		}
		rawCopy := make([]byte, len(raw))
		copy(rawCopy, raw)
		conn.FakeInjectInProgress.Store(true)
		go f.runFakeInjection(rawCopy, conn)
		return
	}

	f.onUnexpectedPacket(raw, conn, "unexpected outbound packet")
}

func (f *passiveFakeTcpInjector) runFakeInjection(rawCopy []byte, conn *FakeInjectiveConnection) {
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
		log.Printf("injector: fake ClientHello sent (%d/%d, %d bytes, %d segment(s))", i+1, repeat, total, segPerInject)
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

func (f *passiveFakeTcpInjector) sendRawPacket(rawIP []byte) error {
	f.linkHdrMu.RLock()
	hdr := f.linkHdr
	f.linkHdrMu.RUnlock()
	if len(hdr) < ethernetHeaderLen {
		return fmt.Errorf("no observed Ethernet header yet for injection")
	}
	frame := make([]byte, ethernetHeaderLen+len(rawIP))
	copy(frame, hdr)
	copy(frame[ethernetHeaderLen:], rawIP)

	var addr [8]byte
	copy(addr[:], hdr[:6])
	f.sendMu.Lock()
	defer f.sendMu.Unlock()
	return unix.Sendto(f.fd, frame, 0, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  f.ifindex,
		Halen:    6,
		Addr:     addr,
	})
}
