package obfs

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

const (
	UDPRelayModeQUIC       = "quic"
	UDPRelayALPN           = "v2ray-plugin-sip003u"
	DefaultUDPRelayTimeout = 30 * time.Second
)

// UDPRelayOption carries the internal client settings for SIP003U UDP relay.
type UDPRelayOption struct {
	ServerAddr     string
	Host           string
	TLS            bool
	ECHConfig      *ech.Config
	SkipCertVerify bool
	Fingerprint    string
	Certificate    string
	PrivateKey     string
	Timeout        time.Duration
	Dialer         C.Dialer
}

type udpRelayPacket struct {
	data []byte
	addr net.Addr
}

type udpRelayClientFlow struct {
	conn     *quic.Conn
	pc       net.PacketConn
	lastSeen time.Time
}

type UDPRelayPacketConn struct {
	option     UDPRelayOption
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	timeout    time.Duration

	access  sync.Mutex
	flows   map[string]*udpRelayClientFlow
	closed  bool
	readCh  chan udpRelayPacket
	closeCh chan struct{}
	once    sync.Once
}

func NewUDPRelayPacketConn(ctx context.Context, option UDPRelayOption) (*UDPRelayPacketConn, error) {
	if option.Dialer == nil {
		return nil, errors.New("missing dialer")
	}
	timeout := udpRelayTimeout(option.Timeout)
	tlsConfig, err := udpRelayClientTLSConfig(option)
	if err != nil {
		return nil, err
	}
	conn := &UDPRelayPacketConn{
		option:     option,
		tlsConfig:  tlsConfig,
		quicConfig: udpRelayQUICConfig(timeout),
		timeout:    timeout,
		flows:      map[string]*udpRelayClientFlow{},
		readCh:     make(chan udpRelayPacket, 1024),
		closeCh:    make(chan struct{}),
	}
	go conn.cleanupLoop()
	return conn, ctx.Err()
}

func (c *UDPRelayPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case packet, ok := <-c.readCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		return copy(p, packet.data), packet.addr, nil
	case <-c.closeCh:
		return 0, nil, net.ErrClosed
	}
}

func (c *UDPRelayPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	flow, err := c.flow(context.Background(), addr)
	if err != nil {
		return 0, err
	}
	if err := flow.conn.SendDatagram(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *UDPRelayPacketConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closeCh)
		c.access.Lock()
		defer c.access.Unlock()
		c.closed = true
		for key, flow := range c.flows {
			err = errors.Join(err, flow.conn.CloseWithError(0, ""))
			err = errors.Join(err, flow.pc.Close())
			delete(c.flows, key)
		}
	})
	return err
}

func (c *UDPRelayPacketConn) LocalAddr() net.Addr {
	return relayAddr(c.option.ServerAddr)
}

func (c *UDPRelayPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (c *UDPRelayPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *UDPRelayPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *UDPRelayPacketConn) flow(ctx context.Context, addr net.Addr) (*udpRelayClientFlow, error) {
	key := addr.String()
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil, net.ErrClosed
	}
	flow := c.flows[key]
	if flow != nil {
		flow.lastSeen = time.Now()
	}
	c.access.Unlock()
	if flow != nil {
		return flow, nil
	}

	flow, err := c.newFlow(ctx, addr)
	if err != nil {
		return nil, err
	}
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		_ = flow.conn.CloseWithError(0, "")
		_ = flow.pc.Close()
		return nil, net.ErrClosed
	}
	if oldFlow := c.flows[key]; oldFlow != nil {
		oldFlow.lastSeen = time.Now()
		c.access.Unlock()
		_ = flow.conn.CloseWithError(0, "")
		_ = flow.pc.Close()
		return oldFlow, nil
	}
	c.flows[key] = flow
	c.access.Unlock()
	go c.readLoop(key, addr, flow)
	return flow, nil
}

func (c *UDPRelayPacketConn) newFlow(ctx context.Context, addr net.Addr) (*udpRelayClientFlow, error) {
	serverAddr, err := netip.ParseAddrPort(c.option.ServerAddr)
	if err != nil {
		return nil, err
	}
	packetConn, err := c.option.Dialer.ListenPacket(ctx, "udp", "", serverAddr)
	if err != nil {
		return nil, err
	}
	transport := quic.Transport{Conn: packetConn}
	transport.SetCreatedConn(true)
	transport.SetSingleUse(true)
	quicConn, err := transport.Dial(ctx, net.UDPAddrFromAddrPort(serverAddr), c.tlsConfig, c.quicConfig)
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}
	return &udpRelayClientFlow{
		conn:     quicConn,
		pc:       packetConn,
		lastSeen: time.Now(),
	}, nil
}

func (c *UDPRelayPacketConn) readLoop(key string, addr net.Addr, flow *udpRelayClientFlow) {
	defer func() {
		c.access.Lock()
		if c.flows[key] == flow {
			delete(c.flows, key)
		}
		c.access.Unlock()
		_ = flow.conn.CloseWithError(0, "")
		_ = flow.pc.Close()
	}()
	for {
		data, err := flow.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		c.access.Lock()
		flow.lastSeen = time.Now()
		c.access.Unlock()
		select {
		case c.readCh <- udpRelayPacket{data: data, addr: addr}:
		case <-c.closeCh:
			return
		}
	}
}

func (c *UDPRelayPacketConn) cleanupLoop() {
	interval := c.timeout / 2
	if interval <= 0 {
		interval = DefaultUDPRelayTimeout / 2
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanupIdleFlows(time.Now())
		case <-c.closeCh:
			return
		}
	}
}

func (c *UDPRelayPacketConn) cleanupIdleFlows(now time.Time) {
	var idleFlows []*udpRelayClientFlow
	c.access.Lock()
	for key, flow := range c.flows {
		if now.Sub(flow.lastSeen) >= c.timeout {
			delete(c.flows, key)
			idleFlows = append(idleFlows, flow)
		}
	}
	c.access.Unlock()

	for _, flow := range idleFlows {
		_ = flow.conn.CloseWithError(0, "")
		_ = flow.pc.Close()
	}
}

func udpRelayTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return DefaultUDPRelayTimeout
	}
	return timeout
}

func udpRelayQUICConfig(timeout time.Duration) *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  timeout,
		KeepAlivePeriod: timeout / 2,
	}
}

func udpRelayClientTLSConfig(option UDPRelayOption) (*tls.Config, error) {
	serverName := option.Host
	if serverName == "" {
		serverName = "bing.com"
	}
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: option.SkipCertVerify,
		NextProtos:         []string{UDPRelayALPN},
	}
	config, err := ca.GetTLSConfig(ca.Option{
		TLSConfig:   tlsConfig,
		Fingerprint: option.Fingerprint,
		Certificate: option.Certificate,
		PrivateKey:  option.PrivateKey,
	})
	if err != nil {
		return nil, err
	}
	if option.ECHConfig != nil {
		if err := option.ECHConfig.ClientHandle(context.Background(), config); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	}
	return config, nil
}

func relayAddr(addr string) net.Addr {
	if udpAddr, err := net.ResolveUDPAddr("udp", addr); err == nil {
		return udpAddr
	}
	return &net.UDPAddr{}
}
