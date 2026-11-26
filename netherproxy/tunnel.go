package netherproxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
)

// TunnelConfig configures a LAN→LAN NetherNet signaling tunnel. The tunnel
// republishes the upstream's own LAN advertisement on the local LAN and relays
// signaling, so the upstream experiences a vanilla LAN join with no HTTP
// signaling and no SDP identity assertions involved. Each LAN client is
// presented upstream under its own network ID (a dedicated upstream listener
// per client), exactly as if it had connected without a proxy; media flows
// directly between the client and the upstream's advertised candidates unless
// MediaAssist is enabled.
type TunnelConfig struct {
	// BindAddr is the downstream LAN bind (clients broadcast here; :7551).
	BindAddr string
	// UpstreamAddr is the upstream NetherNet LAN host as host:port. The port
	// defaults to 7551 when empty.
	UpstreamAddr string
	// NetworkID is the downstream network ID; 0 chooses a random ID.
	NetworkID uint64
	// RouteTTL drops idle connection routes; 0 means 5 minutes.
	RouteTTL time.Duration
	// MediaAssist rewrites the upstream's answer candidates to AdvertiseIP and
	// relays each connection's UDP media through this proxy to the upstream
	// host at the advertised port (peer-IP targeting). For upstreams whose
	// advertised candidates are unreachable from clients, such as a
	// Docker-bridged BDS. Trusted LAN only: endpoints are learned from
	// traffic, not authenticated.
	MediaAssist  bool
	AdvertiseIP  net.IP
	MediaBind    string
	MediaIdleTTL time.Duration
	Logger       *log.Logger
}

// LANTunnel relays NetherNet LAN discovery and signaling between a local LAN
// and one upstream LAN host. It is transparent to SDP contents.
type LANTunnel struct {
	down      *discovery.Listener // LAN side: advertises, receives client signals
	probe     *discovery.Listener // upstream side: learns the advertisement only
	upAddr    *net.UDPAddr
	assist    bool
	advertise net.IP
	mediaBind string
	mediaTTL  time.Duration
	log       *log.Logger
	routeTTL  time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	routes map[uint64]route // connection ID -> owning client
	bdsID  uint64
	peers  map[string]*clientPeer // client network ID -> its upstream identity
}

type route struct {
	client   string
	lastSeen time.Time
	assist   *assistRelay
}

// clientPeer is one LAN client's dedicated upstream identity. Signals from the
// client are forwarded through its own discovery listener, so the upstream
// sees a distinct peer per client. A fresh listener needs a discovery
// response before it can signal (up to ~2s); the ordered queue absorbs that
// delay for the client's first signals without reordering them.
type clientPeer struct {
	clientID string
	l        *discovery.Listener
	queue    chan *nethernet.Signal
	stop     func()
	lastSeen time.Time
}

// assistRelay forwards one connection's UDP media between the client and the
// upstream's published port. Trusted LAN only: the client endpoint is learned
// from its first packet.
type assistRelay struct {
	conn   *net.UDPConn
	target *net.UDPAddr
	mu     sync.Mutex
	client *net.UDPAddr
	// touch refreshes the owning route's idle timestamp so active media
	// keeps the route (and this relay) alive. Nil after the route is gone.
	touch  func()
	log    *log.Logger
	closed chan struct{}
	once   sync.Once
}

func (a *assistRelay) pump(ttl time.Duration) {
	buf := make([]byte, 65535)
	_ = a.conn.SetReadDeadline(time.Now().Add(ttl))
	for {
		n, src, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			a.close()
			return
		}
		_ = a.conn.SetReadDeadline(time.Now().Add(ttl))
		if a.touch != nil {
			a.touch()
		}
		if src.IP.Equal(a.target.IP) && src.Port == a.target.Port {
			a.mu.Lock()
			client := a.client
			a.mu.Unlock()
			if client != nil {
				_, _ = a.conn.WriteToUDP(buf[:n], client)
			}
			continue
		}
		a.mu.Lock()
		if a.client == nil {
			copyAddr := *src
			a.client = &copyAddr
			a.log.Printf("nethernet lan tunnel: assist connection bound to client %s", src)
		}
		a.mu.Unlock()
		_, _ = a.conn.WriteToUDP(buf[:n], a.target)
	}
}

func (a *assistRelay) close() {
	a.once.Do(func() {
		close(a.closed)
		_ = a.conn.Close()
	})
}

const (
	lanTunnelMaxRoutes       = 256
	lanTunnelSweep           = 30 * time.Second
	lanTunnelPeerTTL         = 10 * time.Minute
	lanTunnelPeerQueue       = 128
	lanTunnelForwardTimeout  = 6 * time.Second
	lanTunnelForwardRetryGap = 100 * time.Millisecond
)

// NewLANTunnel starts the tunnel immediately. Call Close to stop it.
func NewLANTunnel(cfg TunnelConfig) (*LANTunnel, error) {
	if cfg.BindAddr == "" {
		cfg.BindAddr = ":7551"
	}
	if cfg.UpstreamAddr == "" {
		return nil, errors.New("nethernet tunnel: UpstreamAddr is required")
	}
	if cfg.RouteTTL == 0 {
		cfg.RouteTTL = 5 * time.Minute
	}
	if cfg.MediaIdleTTL == 0 {
		cfg.MediaIdleTTL = 5 * time.Minute
	}
	if cfg.MediaBind == "" {
		cfg.MediaBind = ":0"
	}
	if cfg.MediaAssist && (cfg.AdvertiseIP == nil || cfg.AdvertiseIP.To4() == nil) {
		return nil, errors.New("nethernet tunnel: MediaAssist requires an IPv4 AdvertiseIP")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	host, portText, err := net.SplitHostPort(cfg.UpstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("nethernet tunnel: invalid UpstreamAddr %q: %w", cfg.UpstreamAddr, err)
	}
	if portText == "" {
		portText = "7551"
	}
	upAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, portText))
	if err != nil {
		return nil, fmt.Errorf("nethernet tunnel: resolve UpstreamAddr: %w", err)
	}

	down, err := (discovery.ListenConfig{NetworkID: cfg.NetworkID}).Listen(cfg.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("nethernet tunnel: downstream listen: %w", err)
	}
	// The probe only learns the upstream's advertisement. Client signaling
	// never travels through it; each client gets a dedicated peer listener.
	probe, err := (discovery.ListenConfig{BroadcastAddress: upAddr}).Listen("0.0.0.0:0")
	if err != nil {
		_ = down.Close()
		return nil, fmt.Errorf("nethernet tunnel: upstream probe listen: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &LANTunnel{
		down:      down,
		probe:     probe,
		upAddr:    upAddr,
		assist:    cfg.MediaAssist,
		advertise: cfg.AdvertiseIP.To4(),
		mediaBind: cfg.MediaBind,
		mediaTTL:  cfg.MediaIdleTTL,
		log:       cfg.Logger,
		routeTTL:  cfg.RouteTTL,
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		routes:    make(map[uint64]route),
		peers:     make(map[string]*clientPeer),
	}
	stopDown := down.Notify(clientForwarder{t})
	go func() {
		defer close(t.done)
		defer stopDown()
		t.learnAdvertisement()
		learn := time.NewTicker(time.Second)
		defer learn.Stop()
		sweep := time.NewTicker(lanTunnelSweep)
		defer sweep.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-learn.C:
				t.learnAdvertisement()
			case <-sweep.C:
				t.sweepRoutes()
				t.sweepPeers()
			}
		}
	}()
	t.log.Printf("nethernet lan tunnel up: downstream %s (network ID %s) -> upstream %s", cfg.BindAddr, down.NetworkID(), upAddr)
	return t, nil
}

// NetworkID returns the tunnel's downstream network ID.
func (t *LANTunnel) NetworkID() string { return t.down.NetworkID() }

// learnAdvertisement republishes the upstream's LAN advertisement downstream.
func (t *LANTunnel) learnAdvertisement() {
	responses := t.probe.Responses()
	if len(responses) == 0 {
		return
	}
	ids := make([]uint64, 0, len(responses))
	for id := range responses {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) > 1 {
		t.log.Printf("nethernet lan tunnel: upstream %d responses; using lowest network ID", len(ids))
	}
	id := ids[0]
	var data discovery.ServerData
	if err := data.UnmarshalBinary(responses[id]); err != nil {
		t.log.Printf("nethernet lan tunnel: decode upstream advertisement: %v", err)
		return
	}
	t.mu.Lock()
	changed := t.bdsID != id
	t.bdsID = id
	t.mu.Unlock()
	if changed {
		t.down.ServerData(&data)
		t.log.Printf("nethernet lan tunnel: republishing upstream %d (%s, protocol %d %s, nonce %q)", id, data.ServerName, data.Protocol, data.Version, data.Nonce)
	}
}

func (t *LANTunnel) upstreamID() (uint64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bdsID, t.bdsID != 0
}

// peerFor returns the client's dedicated upstream identity, creating and
// starting it on first contact. The peer presents the client's own network ID
// upstream, as if the client had connected directly.
func (t *LANTunnel) peerFor(clientID string) *clientPeer {
	t.mu.Lock()
	if p, ok := t.peers[clientID]; ok {
		p.lastSeen = time.Now()
		t.mu.Unlock()
		return p
	}
	t.mu.Unlock()

	id, err := strconv.ParseUint(clientID, 10, 64) // discovery sender IDs are numeric
	if err != nil {
		return nil
	}
	l, err := (discovery.ListenConfig{NetworkID: id, BroadcastAddress: t.upAddr}).Listen("0.0.0.0:0")
	if err != nil {
		t.log.Printf("nethernet lan tunnel: upstream identity for client %s: %v", clientID, err)
		return nil
	}
	p := &clientPeer{clientID: clientID, l: l, queue: make(chan *nethernet.Signal, lanTunnelPeerQueue), lastSeen: time.Now()}
	p.stop = l.Notify(peerForwarder{t: t, clientID: clientID})

	t.mu.Lock()
	if existing, ok := t.peers[clientID]; ok { // lost a creation race
		t.mu.Unlock()
		p.stop()
		_ = l.Close()
		return existing
	}
	t.peers[clientID] = p
	t.mu.Unlock()

	go p.run(t.ctx, t)
	t.log.Printf("nethernet lan tunnel: client %s presents its own identity upstream", clientID)
	return p
}

// run drains the client's signal queue in order, so an offer always precedes
// its candidates even while the fresh listener is still learning the
// upstream's address.
func (p *clientPeer) run(ctx context.Context, t *LANTunnel) {
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-p.queue:
			t.forwardUpstream(p, sig)
		}
	}
}

func (t *LANTunnel) forwardUpstream(p *clientPeer, sig *nethernet.Signal) {
	deadline := time.Now().Add(lanTunnelForwardTimeout)
	for {
		if t.ctx.Err() != nil {
			return
		}
		if upID, ok := t.upstreamID(); ok {
			err := p.l.Signal(t.ctx, &nethernet.Signal{Type: sig.Type, NetworkID: strconv.FormatUint(upID, 10), ConnectionID: sig.ConnectionID, Data: sig.Data})
			if err == nil {
				return
			}
			if t.ctx.Err() != nil {
				return
			}
			// A fresh listener cannot signal until the upstream answers its
			// first discovery request; retry briefly rather than drop.
			if !strings.Contains(err.Error(), "no address found") || time.Now().After(deadline) {
				t.log.Printf("nethernet lan tunnel: forward signal from client %s: %v", p.clientID, err)
				return
			}
		} else if time.Now().After(deadline) {
			t.log.Printf("nethernet lan tunnel: upstream advertisement not learned; dropping signal from client %s", p.clientID)
			return
		}
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(lanTunnelForwardRetryGap):
		}
	}
}

// clientForwarder relays signals from LAN clients to the upstream through
// each client's dedicated identity.
type clientForwarder struct{ t *LANTunnel }

func (f clientForwarder) NotifySignal(s *nethernet.Signal) bool {
	t := f.t
	if len(s.Data) > maxBodySize {
		return false
	}
	t.mu.Lock()
	if len(t.routes) >= lanTunnelMaxRoutes {
		if _, exists := t.routes[s.ConnectionID]; !exists {
			t.mu.Unlock()
			t.log.Printf("nethernet lan tunnel: route table full; dropping signal from %s", s.NetworkID)
			return false
		}
	}
	r := route{client: s.NetworkID, lastSeen: time.Now()}
	if existing, ok := t.routes[s.ConnectionID]; ok {
		r.assist = existing.assist
	}
	t.routes[s.ConnectionID] = r
	if s.Type == nethernet.SignalTypeError {
		if r.assist != nil {
			defer r.assist.close()
		}
		delete(t.routes, s.ConnectionID)
	}
	t.mu.Unlock()

	peer := t.peerFor(s.NetworkID)
	if peer == nil {
		return false
	}
	select {
	case peer.queue <- &nethernet.Signal{Type: s.Type, ConnectionID: s.ConnectionID, Data: s.Data}:
		return true
	default:
		t.log.Printf("nethernet lan tunnel: client %s signal queue full; dropping signal", s.NetworkID)
		return false
	}
}

// peerForwarder relays signals the upstream sends to one client's dedicated
// identity back to that client.
type peerForwarder struct {
	t        *LANTunnel
	clientID string
}

func (f peerForwarder) NotifySignal(s *nethernet.Signal) bool {
	t := f.t
	if len(s.Data) > maxBodySize {
		return false
	}
	t.mu.Lock()
	r, ok := t.routes[s.ConnectionID]
	if ok {
		r.lastSeen = time.Now()
		t.routes[s.ConnectionID] = r
	}
	if s.Type == nethernet.SignalTypeError {
		if r.assist != nil {
			r.assist.close()
		}
		delete(t.routes, s.ConnectionID)
	}
	t.mu.Unlock()
	if !ok {
		t.log.Printf("nethernet lan tunnel: dropping upstream signal for unknown connection %d", s.ConnectionID)
		return false
	}
	if t.assist && s.Type == nethernet.SignalTypeAnswer {
		if rewritten, err := t.assistAnswer(s.ConnectionID, s.Data); err == nil {
			s.Data = rewritten
		} else {
			t.log.Printf("nethernet lan tunnel: connection %d media assist failed (%v); passing answer through", s.ConnectionID, err)
		}
	}
	if err := t.down.Signal(t.ctx, &nethernet.Signal{Type: s.Type, NetworkID: f.clientID, ConnectionID: s.ConnectionID, Data: s.Data}); err != nil {
		t.log.Printf("nethernet lan tunnel: forward answer-side signal for connection %d: %v", s.ConnectionID, err)
	}
	return true
}

// assistAnswer rewrites the answer's ICE candidates to a per-connection UDP
// socket on this proxy and returns the rewritten SDP. Media for that socket is
// forwarded to the upstream host at the advertised candidate port (peer-IP
// targeting), which reaches Docker-bridged upstreams through published ports.
func (t *LANTunnel) assistAnswer(connID uint64, answer string) (string, error) {
	addr, err := net.ResolveUDPAddr("udp4", t.mediaBind)
	if err != nil {
		return "", err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return "", err
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	rewritten, candidates, err := rewriteCandidates(answer, t.advertise.String(), port)
	if err != nil {
		_ = conn.Close()
		return "", err
	}
	target := &net.UDPAddr{IP: t.upAddr.IP, Port: candidates[0].Port}
	a := &assistRelay{conn: conn, target: target, log: t.log, closed: make(chan struct{})}
	a.touch = func() { t.touchRoute(connID) }
	t.mu.Lock()
	if r, ok := t.routes[connID]; ok {
		r.assist = a
		t.routes[connID] = r
	}
	t.mu.Unlock()
	go a.pump(t.mediaTTL)
	t.log.Printf("nethernet lan tunnel: connection %d media via %s:%d -> %s (advertised %s)",
		connID, t.advertise, port, target, candidates[0].String())
	return rewritten, nil
}

// touchRoute marks a connection's route as active. Media traffic calls this
// through the assist relay so live sessions are never reaped as idle.
func (t *LANTunnel) touchRoute(id uint64) {
	t.mu.Lock()
	if r, ok := t.routes[id]; ok {
		r.lastSeen = time.Now()
		t.routes[id] = r
	}
	t.mu.Unlock()
}

func (t *LANTunnel) sweepRoutes() {
	now := time.Now()
	t.mu.Lock()
	var dead []*assistRelay
	for id, r := range t.routes {
		if now.Sub(r.lastSeen) > t.routeTTL {
			if r.assist != nil {
				dead = append(dead, r.assist)
			}
			delete(t.routes, id)
		}
	}
	t.mu.Unlock()
	for _, a := range dead {
		a.close()
	}
}

// sweepPeers retires clients that have not signaled for a while. Their
// identities are recreated instantly (minus the discovery round trip) if they
// return; live media through assist relays is unaffected.
func (t *LANTunnel) sweepPeers() {
	now := time.Now()
	t.mu.Lock()
	var idle []*clientPeer
	for id, p := range t.peers {
		if now.Sub(p.lastSeen) > lanTunnelPeerTTL {
			delete(t.peers, id)
			idle = append(idle, p)
		}
	}
	t.mu.Unlock()
	for _, p := range idle {
		p.stop()
		_ = p.l.Close()
	}
}

// Close stops both sides of the tunnel and every client identity.
func (t *LANTunnel) Close() error {
	t.cancel()
	<-t.done
	t.mu.Lock()
	peers := make([]*clientPeer, 0, len(t.peers))
	for _, p := range t.peers {
		peers = append(peers, p)
	}
	t.peers = make(map[string]*clientPeer)
	t.mu.Unlock()
	for _, p := range peers {
		p.stop()
		_ = p.l.Close()
	}
	errDown := t.down.Close()
	errProbe := t.probe.Close()
	if errDown != nil {
		return errDown
	}
	return errProbe
}
