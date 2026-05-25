//go:build windows

package injection

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	godivert "github.com/one-api/godivert"

	"sni-spoofing-go/connection"
	"sni-spoofing-go/packet"
)

// WinDivert max IPv4 datagram; oversized packets are rare for this use case.
const winDivertRecvBufMax = 65536

type FakeTcpInjector struct {
	wd          *godivert.Divert
	recvBuf     []byte
	Connections sync.Map
	// byLocalPort indexes flows by ephemeral local port when the IPv4 SrcIP on the wire
	// does not match ConnID.SrcIP (e.g. bind to 0.0.0.0 and a route-chosen source address).
	byLocalPort     sync.Map // uint16 -> *FakeInjectiveConnection
	nicMTU          int
	injectorReady   chan struct{}
	injectorOpenErr error
	filter          string

	shutdown  atomic.Bool
	closeOnce sync.Once

	// sendMu serializes sends on the WinDivert handle. Normal reinjection happens
	// from the Recv goroutine; fake injection runs on a dedicated goroutine.
	sendMu sync.Mutex
}

func NewFakeTcpInjector(interfaceIP string, connectIPv4s []string, connectPort uint16) (*FakeTcpInjector, error) {
	if len(connectIPv4s) == 0 {
		return nil, fmt.Errorf("no upstream IPv4 addresses")
	}

	mtu := nicMTUForLocalIPv4(interfaceIP)
	if mtu == 0 {
		log.Printf("injector: fallback MSS %d", fallbackTCPPayloadMax)
	}

	filter := BuildConnectWinDivertFilterAny(connectIPv4s, connectPort)

	return &FakeTcpInjector{
		recvBuf:       make([]byte, winDivertRecvBufMax),
		nicMTU:        mtu,
		injectorReady: make(chan struct{}),
		filter:        filter,
	}, nil
}

func (f *FakeTcpInjector) Start() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	wd, err := godivert.New(f.filter, godivert.LayerNetwork, 0, 0)
	if err != nil {
		f.injectorOpenErr = err
		close(f.injectorReady)
		return nil
	}
	log.Printf("injector: WinDivert ready")
	if f.shutdown.Load() {
		_ = wd.Close()
		f.injectorOpenErr = errors.New("injector shut down during open")
		close(f.injectorReady)
		return nil
	}
	f.wd = wd
	close(f.injectorReady)

	for {
		var addr godivert.Address
		n, err := f.wd.Recv(f.recvBuf, &addr)
		if err != nil {
			if f.shutdown.Load() {
				return nil
			}
			log.Printf("WinDivert recv error: %v", err)
			continue
		}
		if n == 0 {
			continue
		}
		f.inject(f.recvBuf[:n], &addr)
	}
}

func (f *FakeTcpInjector) WaitInjectorReady() error {
	<-f.injectorReady
	return f.injectorOpenErr
}

func (f *FakeTcpInjector) Close() {
	f.shutdown.Store(true)
	f.closeOnce.Do(func() {
		if f.wd != nil {
			_ = f.wd.Close()
		}
	})
}

func (f *FakeTcpInjector) sendPacket(raw []byte, addr *godivert.Address) error {
	if f.shutdown.Load() {
		return nil
	}
	f.sendMu.Lock()
	_, err := f.wd.Send(raw, addr)
	f.sendMu.Unlock()
	if err != nil && !f.shutdown.Load() {
		log.Printf("WinDivert send error: %v", err)
	}
	return err
}

// runFakeInjection injects the fake ClientHello via WinDivert after the third
// handshake ACK is reinjected. Divert uses separate recv/send overlapped events,
// so this can run without blocking the Recv loop.
func (f *FakeTcpInjector) runFakeInjection(rawCopy []byte, addr *godivert.Address, conn *FakeInjectiveConnection) {
	defer conn.FakeInjectInProgress.Store(false)

	time.Sleep(1 * time.Millisecond)

	if !conn.IsMonitoring() {
		return
	}

	if conn.BypassMethod != "wrong_seq" {
		log.Printf("not implemented bypass method: %s", conn.BypassMethod)
		conn.Mu.Lock()
		conn.AbortUnexpectedCloseLocked()
		conn.Mu.Unlock()
		return
	}

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
		if err := injectWrongSeqClientHello(f.nicMTU, rawCopy, conn, conn.IsMonitoring, func(pkt []byte) error {
			return f.sendPacket(pkt, addr)
		}); err != nil {
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
		defer conn.Mu.Unlock()
		if conn.Monitor {
			conn.Monitor = false
			select {
			case conn.T2aChan <- "fake_data_ack_recv":
			default:
			}
		}
	}
}

func (f *FakeTcpInjector) onUnexpectedPacket(raw []byte, addr *godivert.Address, conn *FakeInjectiveConnection, info string) {
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
	_ = f.sendPacket(raw, addr)
}

func (f *FakeTcpInjector) onInboundPacket(raw []byte, addr *godivert.Address, conn *FakeInjectiveConnection) {
	if conn.SynSeq == -1 {
		f.onUnexpectedPacket(raw, addr, conn, "unexpected inbound packet, no syn sent!")
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.ACK && flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		if conn.SynAckSeq != -1 && conn.SynAckSeq != int64(seqNum) {
			f.onUnexpectedPacket(raw, addr, conn,
				fmt.Sprintf("unexpected inbound syn-ack, seq change! %d %d", seqNum, conn.SynAckSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if ackNum != expectedAck {
			f.onUnexpectedPacket(raw, addr, conn,
				fmt.Sprintf("unexpected inbound syn-ack, ack not matched! %d %d", ackNum, conn.SynSeq))
			return
		}
		conn.SynAckSeq = int64(seqNum)
		_ = f.sendPacket(raw, addr)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && conn.FakeInjectInProgress.Load() && !conn.FakeSent.Load() {
		conn.PostFakeAckObserved.Store(true)
		_ = f.sendPacket(raw, addr)
		return
	}

	// CDNs differ on seq/ack fields after the wrong-seq fake; accept a strict match or a peer ACK.
	if flags.ACK && !flags.SYN && !flags.RST && conn.FakeSent.Load() && conn.SynAckSeq != -1 {
		strict := postFakeInboundStrictOK(seqNum, ackNum, conn)
		permissive := postFakeInboundPermissiveOK(flags)
		if !strict && !permissive {
			f.onUnexpectedPacket(raw, addr, conn,
				fmt.Sprintf("unexpected inbound after fake seq=%d ack=%d synAck=%d syn=%d strict=%v", seqNum, ackNum, conn.SynAckSeq, conn.SynSeq, strict))
			return
		}
		conn.Monitor = false
		_ = f.sendPacket(raw, addr)
		select {
		case conn.T2aChan <- "fake_data_ack_recv":
		default:
		}
		return
	}

	f.onUnexpectedPacket(raw, addr, conn, "unexpected inbound packet")
}

func (f *FakeTcpInjector) onOutboundPacket(raw []byte, addr *godivert.Address, conn *FakeInjectiveConnection) {
	// Until the server ACK is handled (Monitor cleared), reinject every outbound packet:
	// - TCP may retransmit the third handshake ACK
	// - WinDivert may deliver our own injected wrong-seq segments back to Recv; those must not abort.
	if conn.FakeSent.Load() {
		_ = f.sendPacket(raw, addr)
		return
	}
	if conn.FakeInjectInProgress.Load() {
		_ = f.sendPacket(raw, addr)
		return
	}

	flags := packet.GetTCPFlags(raw)
	payloadLen := packet.TCPPayloadLen(raw)
	seqNum := packet.TCPSeqNum(raw)
	ackNum := packet.TCPAckNum(raw)

	if flags.SYN && !flags.ACK && !flags.RST && !flags.FIN && payloadLen == 0 {
		if ackNum != 0 {
			f.onUnexpectedPacket(raw, addr, conn, "unexpected outbound syn, ack_num is not zero!")
			return
		}
		if conn.SynSeq != -1 && conn.SynSeq != int64(seqNum) {
			f.onUnexpectedPacket(raw, addr, conn,
				fmt.Sprintf("unexpected outbound syn, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		conn.SynSeq = int64(seqNum)
		_ = f.sendPacket(raw, addr)
		return
	}

	if flags.ACK && !flags.SYN && !flags.RST && !flags.FIN && payloadLen == 0 {
		expectedSeq := uint32((uint32(conn.SynSeq) + 1) & 0xffffffff)
		if conn.SynSeq == -1 || expectedSeq != seqNum {
			f.onUnexpectedPacket(raw, addr, conn,
				fmt.Sprintf("unexpected outbound ack, seq not matched! %d %d", seqNum, conn.SynSeq))
			return
		}
		expectedAck := uint32((uint32(conn.SynAckSeq) + 1) & 0xffffffff)
		if conn.SynAckSeq == -1 || ackNum != expectedAck {
			f.onUnexpectedPacket(raw, addr, conn,
				fmt.Sprintf("unexpected outbound ack, ack not matched! %d %d", ackNum, conn.SynAckSeq))
			return
		}
		_ = f.sendPacket(raw, addr)

		rawCopy := make([]byte, len(raw))
		copy(rawCopy, raw)
		addrCopy := *addr
		conn.FakeInjectInProgress.Store(true)
		go f.runFakeInjection(rawCopy, &addrCopy, conn)
		return
	}

	f.onUnexpectedPacket(raw, addr, conn, "unexpected outbound packet")
}

func (f *FakeTcpInjector) inject(raw []byte, addr *godivert.Address) {
	if len(raw) < 40 {
		_ = f.sendPacket(raw, addr)
		return
	}

	if packet.IPVersion(raw) != 4 {
		_ = f.sendPacket(raw, addr)
		return
	}

	srcIP := packet.IPv4SrcAddr(raw).String()
	dstIP := packet.IPv4DstAddr(raw).String()
	srcPort := packet.TCPSrcPort(raw)
	dstPort := packet.TCPDstPort(raw)

	// Classify by registered 4-tuple only. WinDivert ADDRESS uses bitfields; one-api's Outbound() bit
	// may not match the driver ABI — infer direction from packet IPs/ports vs ConnID instead.
	conn, outbound, ok := f.lookupConnQuad(srcIP, srcPort, dstIP, dstPort)
	if !ok {
		_ = f.sendPacket(raw, addr)
		return
	}

	c := conn
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if !c.Monitor {
		_ = f.sendPacket(raw, addr)
		return
	}
	if outbound {
		f.onOutboundPacket(raw, addr, c)
	} else {
		f.onInboundPacket(raw, addr, c)
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
			f.bindObservedTuple(c, srcIP, srcPort)
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

func (f *FakeTcpInjector) RegisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Store(conn.ID, conn)
	f.byLocalPort.Store(conn.SrcPort, conn)
}

func (f *FakeTcpInjector) UnregisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Delete(conn.ID)
	f.byLocalPort.Delete(conn.SrcPort)
}

func (f *FakeTcpInjector) bindObservedTuple(conn *FakeInjectiveConnection, srcIP string, srcPort uint16) {
	if srcPort == 0 {
		return
	}
	conn.Mu.Lock()
	defer conn.Mu.Unlock()
	if conn.SrcPort == srcPort && ipv4Equal(conn.SrcIP, srcIP) {
		return
	}
	oldID := conn.ID
	oldPort := conn.SrcPort
	conn.SrcIP = srcIP
	conn.SrcPort = srcPort
	conn.ID = connection.ConnID{
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   conn.DstIP,
		DstPort: conn.DstPort,
	}
	f.Connections.Delete(oldID)
	f.byLocalPort.Delete(oldPort)
	f.Connections.Store(conn.ID, conn)
	f.byLocalPort.Store(srcPort, conn)
}
