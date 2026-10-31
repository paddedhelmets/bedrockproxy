package netherproxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
)

// TunnelConfig configures a LAN→LAN NetherNet signaling tunnel. The bridge
// republishes the upstream's own LAN advertisement on the local LAN and relays
// signaling verbatim, so the upstream experiences a vanilla LAN join with no
// HTTP signaling and no SDP identity assertions involved. Media flows directly
// between the client and the upstream's advertised candidates.
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
	Logger   *log.Logger
}

// LANTunnel relays NetherNet LAN discovery and signaling between a local LAN
// and one upstream LAN host. It is transparent to SDP contents.
type LANTunnel struct {
	down, up *discovery.Listener
	log      *log.Logger
	routeTTL time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	routes map[uint64]route // connection ID -> client network ID
	bdsID  uint64
}

type route struct {
	client   string
	lastSeen time.Time
}

const (
	lanTunnelMaxRoutes = 256
	lanTunnelSweep     = 30 * time.Second
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
	up, err := (discovery.ListenConfig{BroadcastAddress: upAddr}).Listen("0.0.0.0:0")
	if err != nil {
		_ = down.Close()
		return nil, fmt.Errorf("nethernet tunnel: upstream listen: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &LANTunnel{
		down:     down,
		up:       up,
		log:      cfg.Logger,
		routeTTL: cfg.RouteTTL,
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
		routes:   make(map[uint64]route),
	}
	stopDown := down.Notify(clientForwarder{t})
	stopUp := up.Notify(upstreamForwarder{t})
	go func() {
		defer close(t.done)
		defer stopUp()
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
	responses := t.up.Responses()
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

// clientForwarder relays signals from LAN clients to the upstream.
type clientForwarder struct{ t *LANTunnel }

func (f clientForwarder) NotifySignal(s *nethernet.Signal) bool {
	t := f.t
	if len(s.Data) > maxBodySize {
		return false
	}
	upID, ok := t.upstreamID()
	if !ok {
		t.log.Printf("nethernet lan tunnel: dropping signal from %s (upstream advertisement not learned yet)", s.NetworkID)
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
	t.routes[s.ConnectionID] = route{client: s.NetworkID, lastSeen: time.Now()}
	t.mu.Unlock()
	if err := t.up.Signal(t.ctx, &nethernet.Signal{Type: s.Type, NetworkID: strconv.FormatUint(upID, 10), ConnectionID: s.ConnectionID, Data: s.Data}); err != nil {
		t.log.Printf("nethernet lan tunnel: forward offer-side signal from %s: %v", s.NetworkID, err)
	}
	return true
}

// upstreamForwarder relays signals from the upstream to the LAN client that
// owns the connection.
type upstreamForwarder struct{ t *LANTunnel }

func (f upstreamForwarder) NotifySignal(s *nethernet.Signal) bool {
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
		delete(t.routes, s.ConnectionID)
	}
	t.mu.Unlock()
	if !ok {
		t.log.Printf("nethernet lan tunnel: dropping upstream signal for unknown connection %d", s.ConnectionID)
		return false
	}
	if err := t.down.Signal(t.ctx, &nethernet.Signal{Type: s.Type, NetworkID: r.client, ConnectionID: s.ConnectionID, Data: s.Data}); err != nil {
		t.log.Printf("nethernet lan tunnel: forward answer-side signal for connection %d: %v", s.ConnectionID, err)
	}
	return true
}

func (t *LANTunnel) sweepRoutes() {
	now := time.Now()
	t.mu.Lock()
	for id, r := range t.routes {
		if now.Sub(r.lastSeen) > t.routeTTL {
			delete(t.routes, id)
		}
	}
	t.mu.Unlock()
}

// Close stops both listeners and the background loops.
func (t *LANTunnel) Close() error {
	t.cancel()
	errDown := t.down.Close()
	errUp := t.up.Close()
	<-t.done
	if errDown != nil {
		return errDown
	}
	return errUp
}
