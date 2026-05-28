//go:build windows

package injection

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	godivert "github.com/one-api/godivert"

	"sni-spoofing-go/connection"
	"sni-spoofing-go/packet"
)

type passiveWinDivertInjector struct {
	sniff       *godivert.Divert
	inject      *godivert.Divert
	recvBuf     []byte
	Connections sync.Map
	byLocalPort sync.Map
	nicMTU      int
	filter      string

	injectorReady   chan struct{}
	injectorOpenErr error
	shutdown        atomic.Bool
	closeOnce       sync.Once
	sendMu          sync.Mutex
}

func newPassiveWinDivertInjector(interfaceIP string, connectIPv4s []string, connectPort uint16) (TCPInjector, error) {
	if len(connectIPv4s) == 0 {
		return nil, fmt.Errorf("no upstream IPv4 addresses")
	}
	mtu := nicMTUForLocalIPv4(interfaceIP)
	if mtu == 0 {
		log.Printf("injector: fallback MSS %d", fallbackTCPPayloadMax)
	}
	return &passiveWinDivertInjector{
		recvBuf:       make([]byte, winDivertRecvBufMax),
		nicMTU:        mtu,
		filter:        BuildConnectWinDivertFilterAny(connectIPv4s, connectPort),
		injectorReady: make(chan struct{}),
	}, nil
}

func (f *passiveWinDivertInjector) Start() error {
	sniff, err := godivert.New(f.filter, godivert.LayerNetwork, 0, godivert.FlagSniff|godivert.FlagRecvOnly)
	if err != nil {
		f.injectorOpenErr = fmt.Errorf("open sniff handle: %w", err)
		close(f.injectorReady)
		return nil
	}
	inject, err := godivert.New("false", godivert.LayerNetwork, 0, godivert.FlagSendOnly)
	if err != nil {
		_ = sniff.Close()
		f.injectorOpenErr = fmt.Errorf("open inject handle: %w", err)
		close(f.injectorReady)
		return nil
	}
	if f.shutdown.Load() {
		_ = sniff.Close()
		_ = inject.Close()
		f.injectorOpenErr = fmt.Errorf("injector shut down during open")
		close(f.injectorReady)
		return nil
	}

	f.sniff = sniff
	f.inject = inject
	log.Printf("injector: WinDivert passive ready")
	close(f.injectorReady)

	for {
		var addr godivert.Address
		n, err := f.sniff.Recv(f.recvBuf, &addr)
		if err != nil {
			if f.shutdown.Load() {
				return nil
			}
			log.Printf("WinDivert passive recv error: %v", err)
			continue
		}
		if n == 0 {
			continue
		}
		f.onPacket(f.recvBuf[:n])
	}
}

func (f *passiveWinDivertInjector) WaitInjectorReady() error {
	<-f.injectorReady
	return f.injectorOpenErr
}

func (f *passiveWinDivertInjector) Close() {
	f.shutdown.Store(true)
	f.closeOnce.Do(func() {
		if f.sniff != nil {
			_ = f.sniff.Close()
		}
		if f.inject != nil {
			_ = f.inject.Close()
		}
	})
}

func (f *passiveWinDivertInjector) RegisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Store(conn.ID, conn)
	f.byLocalPort.Store(conn.SrcPort, conn)
}

func (f *passiveWinDivertInjector) UnregisterConn(conn *FakeInjectiveConnection) {
	f.Connections.Delete(conn.ID)
	f.byLocalPort.Delete(conn.SrcPort)
}

func (f *passiveWinDivertInjector) sendPacket(raw []byte) error {
	if f.shutdown.Load() {
		return nil
	}
	var addr godivert.Address
	addr.SetOutbound(true)
	f.sendMu.Lock()
	_, err := f.inject.Send(raw, &addr)
	f.sendMu.Unlock()
	if err != nil && !f.shutdown.Load() {
		log.Printf("WinDivert passive send error: %v", err)
	}
	return err
}

func (f *passiveWinDivertInjector) onPacket(raw []byte) {
	if len(raw) < 40 || packet.IPVersion(raw) != 4 {
		return
	}
	srcIP := packet.IPv4SrcAddr(raw).String()
	dstIP := packet.IPv4DstAddr(raw).String()
	srcPort := packet.TCPSrcPort(raw)
	dstPort := packet.TCPDstPort(raw)

	conn, outbound, ok := f.lookupConnQuad(srcIP, srcPort, dstIP, dstPort)
	if !ok {
		return
	}
	c := conn
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if !c.Monitor {
		return
	}
	if outbound {
		f.onOutboundPacket(raw, c)
	} else {
		f.onInboundPacket(raw, c)
	}
}

func (f *passiveWinDivertInjector) lookupConnQuad(srcIP string, srcPort uint16, dstIP string, dstPort uint16) (conn *FakeInjectiveConnection, outbound bool, ok bool) {
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

func (f *passiveWinDivertInjector) bindObservedTuple(conn *FakeInjectiveConnection, srcIP string, srcPort uint16) {
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

func (f *passiveWinDivertInjector) onUnexpectedPacket(raw []byte, conn *FakeInjectiveConnection, info string) {
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

func (f *passiveWinDivertInjector) onInboundPacket(raw []byte, conn *FakeInjectiveConnection) {
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

func (f *passiveWinDivertInjector) onOutboundPacket(raw []byte, conn *FakeInjectiveConnection) {
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

func (f *passiveWinDivertInjector) runFakeInjection(rawCopy []byte, conn *FakeInjectiveConnection) {
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
		if err := injectWrongSeqClientHello(f.nicMTU, rawCopy, conn, conn.IsMonitoring, f.sendPacket); err != nil {
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
