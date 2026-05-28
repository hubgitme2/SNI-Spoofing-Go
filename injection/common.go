package injection

import (
	"net"
	"sync/atomic"
	"time"

	"sni-spoofing-go/connection"
)

type ConnID = connection.ConnID

type TCPInjector interface {
	Start() error
	WaitInjectorReady() error
	Close()
	RegisterConn(conn *FakeInjectiveConnection)
	UnregisterConn(conn *FakeInjectiveConnection)
}

type InjectorMode string

const (
	InjectorModeActive  InjectorMode = "active"
	InjectorModePassive InjectorMode = "passive"
)

type FakeInjectiveConnection struct {
	*connection.MonitorConnection

	FakeData      []byte
	FakeSent      atomic.Bool
	T2aChan       chan string
	BypassMethod  string
	PeerSock      net.Conn
	FakeRepeat    int
	FakeDelay     time.Duration
	FragmentDelay time.Duration

	// FakeInjectInProgress is set while wrong-seq fake ClientHello is being sent (async off the nfqueue/WinDivert recv path).
	FakeInjectInProgress atomic.Bool
	PostFakeAckObserved  atomic.Bool
}

func NewFakeInjectiveConnection(
	sock net.Conn, srcIP, dstIP string, srcPort, dstPort uint16,
	fakeData []byte, bypassMethod string, peerSock net.Conn,
	fakeRepeat int,
	fakeDelay, fragmentDelay time.Duration,
) *FakeInjectiveConnection {
	if fakeRepeat < 1 {
		fakeRepeat = 1
	}
	return &FakeInjectiveConnection{
		MonitorConnection: connection.NewMonitorConnection(sock, srcIP, dstIP, srcPort, dstPort),
		FakeData:          fakeData,
		// Buffer 2 so a rare second signal (e.g. unexpected + ack) is not dropped before the proxy reads.
		T2aChan:       make(chan string, 2),
		BypassMethod:  bypassMethod,
		PeerSock:      peerSock,
		FakeRepeat:    fakeRepeat,
		FakeDelay:     fakeDelay,
		FragmentDelay: fragmentDelay,
	}
}

func (conn *FakeInjectiveConnection) AbortUnexpectedCloseLocked() {
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

func (conn *FakeInjectiveConnection) IsMonitoring() bool {
	conn.Mu.Lock()
	defer conn.Mu.Unlock()
	return conn.Monitor
}
