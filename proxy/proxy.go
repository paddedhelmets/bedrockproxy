// Package proxy implements the BedrockTogether-equivalent LAN relay.
//
// It runs on a device on the target LAN, listens on the Bedrock port (default
// UDP 19132), and for each console on the LAN it (a) answers RakNet unconnected
// pings with a spoofed pong advertising a configured REMOTE server's MOTD, and
// (b) transparently relays every other datagram between the console and that
// remote server. The console therefore discovers a "LAN game" whose connection
// target is this proxy, and the proxy shuttles the full RakNet game session
// (OpenConnection handshake, framed datagrams, ECDH/AES handshake bytes — all
// opaque to us) to the real server elsewhere on the internet.
//
// Why a relay and not just an advertiser: a RakNet pong carries no address
// field — the client connects back to the UDP source of the pong, which is this
// proxy. So to reach a remote server, we must proxy the bytes. Verified across
// facebookarchive/RakNet, JRakNet, go-raknet, CloudburstMC. See
// docs/reference-bedrock-lan-spoof.md §7.
package proxy

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/paddedhelmets/bedrockproxy/raknet"
)

// mtu is the relay read buffer. RakNet datagrams are typically <= ~1400 bytes
// but the negotiated MTU may be larger; use a full-size buffer to be safe.
const mtu = 65535

// Config controls a Server.
type Config struct {
	BindAddr       string        // LAN-facing listen address (default ":19132")
	RemoteAddr     string        // remote Bedrock server host:port (required)
	Motd           string        // override MOTD line 1; "" = mirror remote
	SubMotd        string        // override MOTD line 2; "" = mirror remote
	ProtocolVer    string        // override protocol version; "" = mirror remote
	ProbeTimeout   time.Duration // remote MOTD probe timeout (default 3s)
	RefreshEvery   time.Duration // re-probe remote MOTD interval; 0 = once
	SessionIdleTTL time.Duration // reap idle upstream sessions (default 5m)
	Logger         *log.Logger
}

// Server is the LAN-spoof relay.
type Server struct {
	cfg      Config
	conn     *net.UDPConn // LAN-facing
	remote   *net.UDPAddr
	serverID int64

	motdMu sync.RWMutex
	motd   *raknet.Motd

	sessionsMu sync.Mutex
	sessions   map[string]*session

	// NetherNet relay: TCP signaling listener on the same port, sessions keyed
	// by ICE username and by the console address once bound.
	tcp         net.Listener
	http        *http.Client
	nnMu        sync.Mutex
	nnSessions  map[string]*nnSession
	nnByConsole map[string]*nnSession

	log *log.Logger
}

// session is one console<->remote relay pair.
type session struct {
	console  *net.UDPAddr
	upstream *net.UDPConn
	lastSeen time.Time
}

// New resolves addresses and binds the LAN-facing UDP socket.
func New(cfg Config) (*Server, error) {
	if cfg.RemoteAddr == "" {
		return nil, fmt.Errorf("config: RemoteAddr is required")
	}
	if cfg.ProbeTimeout == 0 {
		cfg.ProbeTimeout = 3 * time.Second
	}
	if cfg.SessionIdleTTL == 0 {
		cfg.SessionIdleTTL = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}

	addr, err := net.ResolveUDPAddr("udp4", cfg.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve bind %q: %w", cfg.BindAddr, err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.BindAddr, err)
	}
	remote, err := net.ResolveUDPAddr("udp4", cfg.RemoteAddr)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("resolve remote %q: %w", cfg.RemoteAddr, err)
	}
	tcp, err := net.Listen("tcp4", cfg.BindAddr)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("listen tcp %s (NetherNet signaling): %w", cfg.BindAddr, err)
	}

	return &Server{
		cfg:         cfg,
		conn:        conn,
		remote:      remote,
		serverID:    rand.Int63(),
		sessions:    make(map[string]*session),
		tcp:         tcp,
		http:        &http.Client{Timeout: signalTimeout},
		nnSessions:  make(map[string]*nnSession),
		nnByConsole: make(map[string]*nnSession),
		log:         cfg.Logger,
	}, nil
}

// Serve probes the remote for its MOTD, starts helpers, and runs the main
// dispatch loop until ctx is cancelled or a fatal read error occurs.
func (s *Server) Serve(ctx context.Context) error {
	if err := s.refreshMotd(); err != nil {
		s.log.Printf("warning: initial remote probe failed: %v — using fallback MOTD", err)
	}
	if s.motd == nil {
		s.motd = raknet.DefaultMotd(s.serverID)
	}
	if s.cfg.RefreshEvery > 0 {
		go s.motdRefresher(ctx)
	}
	go s.sessionReaper(ctx)
	go func() {
		if err := s.serveSignaling(ctx); err != nil {
			s.log.Printf("nethernet signaling stopped: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = s.conn.Close()
	}()

	s.log.Printf("bedrockproxy up: %s -> %s (serverID=%d, proto=%s motd=%q)",
		s.cfg.BindAddr, s.cfg.RemoteAddr, s.serverID, s.motd.ProtocolVersion, s.motd.Motd)

	buf := make([]byte, mtu)
	for {
		n, console, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("lan read: %w", err)
		}
		s.handle(buf[:n], console)
	}
}

// handle dispatches one inbound datagram from the LAN.
func (s *Server) handle(b []byte, console *net.UDPAddr) {
	if raknet.IsUnconnectedPing(b) {
		s.motdMu.RLock()
		motd := s.motd
		s.motdMu.RUnlock()
		var motdBytes []byte
		if motd != nil {
			motdBytes = []byte(motd.String())
		}
		pong := raknet.BuildPong(raknet.PingTime(b), s.serverID, motdBytes)
		if _, err := s.conn.WriteToUDP(pong, console); err != nil {
			s.log.Printf("pong write to %s: %v", console, err)
		}
		return
	}
	if s.handleNetherNet(b, console) {
		return
	}
	// Anything else is RakNet connection / game traffic — relay to the remote.
	sess, err := s.getOrCreateSession(console)
	if err != nil {
		s.log.Printf("session %s: %v", console, err)
		return
	}
	sess.lastSeen = time.Now()
	if _, err := sess.upstream.Write(b); err != nil {
		s.log.Printf("upstream write from %s: %v", console, err)
		s.closeSession(sess)
	}
}

// getOrCreateSession returns the relay session for a console, opening a fresh
// upstream UDP socket (and a downstream pump goroutine) on first contact.
func (s *Server) getOrCreateSession(console *net.UDPAddr) (*session, error) {
	key := console.String()
	s.sessionsMu.Lock()
	if sess, ok := s.sessions[key]; ok {
		s.sessionsMu.Unlock()
		return sess, nil
	}
	upstream, err := net.DialUDP("udp4", nil, s.remote)
	if err != nil {
		s.sessionsMu.Unlock()
		return nil, err
	}
	sess := &session{console: console, upstream: upstream, lastSeen: time.Now()}
	s.sessions[key] = sess
	s.sessionsMu.Unlock()

	go s.relayDownstream(sess)
	s.log.Printf("session open: %s via %s -> %s", console, upstream.LocalAddr(), s.cfg.RemoteAddr)
	return sess, nil
}

// relayDownstream pumps remote->console bytes for one session until the
// upstream errors (closed, ICMP unreachable, etc.), then tears it down.
func (s *Server) relayDownstream(sess *session) {
	buf := make([]byte, mtu)
	for {
		n, err := sess.upstream.Read(buf)
		if err != nil {
			s.closeSession(sess)
			return
		}
		if _, err := s.conn.WriteToUDP(buf[:n], sess.console); err != nil {
			s.closeSession(sess)
			return
		}
		sess.lastSeen = time.Now()
	}
}

// closeSession removes and closes a session exactly once.
func (s *Server) closeSession(sess *session) {
	s.sessionsMu.Lock()
	_, ok := s.sessions[sess.console.String()]
	if ok {
		delete(s.sessions, sess.console.String())
	}
	s.sessionsMu.Unlock()
	if ok {
		_ = sess.upstream.Close()
		s.log.Printf("session closed: %s", sess.console)
	}
}

// sessionReaper drops sessions that have seen no traffic for SessionIdleTTL.
func (s *Server) sessionReaper(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cutoff := time.Now().Add(-s.cfg.SessionIdleTTL)
			var dead []*session
			s.sessionsMu.Lock()
			for k, sess := range s.sessions {
				if sess.lastSeen.Before(cutoff) {
					dead = append(dead, sess)
					delete(s.sessions, k)
				}
			}
			s.sessionsMu.Unlock()
			for _, sess := range dead {
				_ = sess.upstream.Close()
				s.log.Printf("reaped idle session: %s", sess.console)
			}
			s.reapNetherNet()
		}
	}
}

// motdRefresher periodically re-probes the remote so advertised player counts
// and version stay current (and a remote restart is reflected).
func (s *Server) motdRefresher(ctx context.Context) {
	t := time.NewTicker(s.cfg.RefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.refreshMotd(); err != nil {
				s.log.Printf("motd refresh failed: %v (keeping previous)", err)
			}
		}
	}
}

// refreshMotd probes the remote and stores its MOTD (with operator overrides and
// our display ports applied). It tries a RakNet unconnected ping first, then the
// NetherNet GET /v1/join endpoint (NetherNet-only servers don't answer pings).
func (s *Server) refreshMotd() error {
	motd, rakErr := s.probeRakNet()
	if rakErr != nil {
		var err error
		if motd, err = s.probeJoinInfo(); err != nil {
			return fmt.Errorf("raknet: %v; nethernet: %w", rakErr, err)
		}
	}
	if s.cfg.Motd != "" {
		motd.Motd = s.cfg.Motd
	}
	if s.cfg.SubMotd != "" {
		motd.SubMotd = s.cfg.SubMotd
	}
	if s.cfg.ProtocolVer != "" {
		motd.ProtocolVersion = s.cfg.ProtocolVer
	}
	if la, ok := s.conn.LocalAddr().(*net.UDPAddr); ok {
		motd.IPv4Port = strconv.Itoa(la.Port)
	}
	motd.ServerID = strconv.FormatInt(s.serverID, 10)

	s.motdMu.Lock()
	changed := s.motd == nil || s.motd.String() != motd.String()
	s.motd = motd
	s.motdMu.Unlock()
	if changed {
		s.log.Printf("motd refreshed: proto=%s version=%s motd=%q", motd.ProtocolVersion, motd.VersionName, motd.Motd)
	}
	return nil
}

// probeRakNet sends the remote an unconnected ping and parses its pong MOTD.
func (s *Server) probeRakNet() (*raknet.Motd, error) {
	probe, err := net.DialUDP("udp4", nil, s.remote)
	if err != nil {
		return nil, err
	}
	defer probe.Close()
	if err := probe.SetReadDeadline(time.Now().Add(s.cfg.ProbeTimeout)); err != nil {
		return nil, err
	}
	if _, err := probe.Write(raknet.BuildPing(time.Now().UnixMilli(), s.serverID)); err != nil {
		return nil, err
	}
	buf := make([]byte, mtu)
	n, err := probe.Read(buf)
	if err != nil {
		return nil, err
	}
	pong, err := raknet.ParsePong(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("parse remote pong: %w", err)
	}
	if pong.Motd == nil {
		return raknet.DefaultMotd(s.serverID), nil
	}
	return pong.Motd, nil
}
