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
	"strconv"
	"sync"
	"time"

	"github.com/paddedhelmets/bedrockproxy/raknet"
	"golang.org/x/net/ipv4"
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
	conn     *net.UDPConn     // LAN-facing
	pc       *ipv4.PacketConn // wraps conn; lets us reply from the addressed IP on multi-homed hosts
	remote   *net.UDPAddr
	serverID int64

	motdMu sync.RWMutex
	motd   *raknet.Motd

	sessionsMu sync.Mutex
	sessions   map[string]*session

	log *log.Logger
}

// session is one console<->remote relay pair.
type session struct {
	console  *net.UDPAddr
	upstream *net.UDPConn
	lastSeen time.Time
	local    net.IP // local address the console targets; downstream replies source from here
	ifIndex  int
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

	return &Server{
		cfg:      cfg,
		conn:     conn,
		remote:   remote,
		serverID: rand.Int63(),
		sessions: make(map[string]*session),
		log:      cfg.Logger,
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

	s.log.Printf("bedrockproxy up: %s -> %s (serverID=%d, proto=%s motd=%q)",
		s.cfg.BindAddr, s.cfg.RemoteAddr, s.serverID, s.motd.ProtocolVersion, s.motd.Motd)

	// Enable IP_PKTINFO so replies (pong + relayed game traffic) are sourced from
	// the exact local address a console targeted. Required on multi-homed hosts
	// (e.g. a Pi on wifi + ethernet): without it the kernel's route-chosen source
	// can differ from the addressed IP and the console drops the mismatched reply.
	s.pc = ipv4.NewPacketConn(s.conn)
	if err := s.pc.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		s.log.Printf("warning: IP_PKTINFO unavailable; multi-homed reply-source fix inactive: %v", err)
	}

	// Closing the socket on shutdown unblocks the read below so that
	// Ctrl-C / SIGTERM exits the process cleanly instead of hanging.
	go func() {
		<-ctx.Done()
		s.log.Printf("shutting down...")
		s.conn.Close()
	}()

	buf := make([]byte, mtu)
	for {
		n, cm, src, err := s.pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("lan read: %w", err)
		}
		console := src.(*net.UDPAddr)
		var dst net.IP
		var ifx int
		if cm != nil {
			dst = cm.Dst
			ifx = cm.IfIndex
		}
		s.handle(buf[:n], console, dst, ifx)
	}
}

// writeTo sends b to addr, sourced from localIP when IP_PKTINFO is available
// (so multi-homed hosts reply from the address the client actually targeted).
func (s *Server) writeTo(b []byte, addr *net.UDPAddr, localIP net.IP, ifIndex int) error {
	if len(localIP) != 0 {
		// Force the source IP to the address the client targeted (IP_PKTINFO); let
		// the kernel route to the client normally (do NOT pin IfIndex — the client
		// may be reachable via a different interface than the packet arrived on).
		_, err := s.pc.WriteTo(b, &ipv4.ControlMessage{Src: localIP}, addr)
		return err
	}
	_, err := s.conn.WriteToUDP(b, addr)
	return err
}

// handle dispatches one inbound datagram from the LAN.
func (s *Server) handle(b []byte, console *net.UDPAddr, localIP net.IP, ifIndex int) {
	if raknet.IsUnconnectedPing(b) {
		s.motdMu.RLock()
		motd := s.motd
		s.motdMu.RUnlock()
		var motdBytes []byte
		if motd != nil {
			motdBytes = []byte(motd.String())
		}
		pong := raknet.BuildPong(raknet.PingTime(b), s.serverID, motdBytes)
		if err := s.writeTo(pong, console, localIP, ifIndex); err != nil {
			s.log.Printf("pong write to %s: %v", console, err)
		}
		return
	}
	// Anything else is connection / game traffic — relay to the remote.
	sess, err := s.getOrCreateSession(console)
	if err != nil {
		s.log.Printf("session %s: %v", console, err)
		return
	}
	sess.local = localIP
	sess.ifIndex = ifIndex
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
		if err := s.writeTo(buf[:n], sess.console, sess.local, sess.ifIndex); err != nil {
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

// refreshMotd probes the remote with an unconnected ping and stores the parsed
// MOTD (with operator overrides and our display ports applied).
func (s *Server) refreshMotd() error {
	probe, err := net.DialUDP("udp4", nil, s.remote)
	if err != nil {
		return err
	}
	defer probe.Close()
	if err := probe.SetReadDeadline(time.Now().Add(s.cfg.ProbeTimeout)); err != nil {
		return err
	}
	if _, err := probe.Write(raknet.BuildPing(time.Now().UnixMilli(), s.serverID)); err != nil {
		return err
	}
	buf := make([]byte, mtu)
	n, err := probe.Read(buf)
	if err != nil {
		return err
	}
	pong, err := raknet.ParsePong(buf[:n])
	if err != nil {
		return fmt.Errorf("parse remote pong: %w", err)
	}
	motd := pong.Motd
	if motd == nil {
		motd = raknet.DefaultMotd(s.serverID)
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
	s.motd = motd
	s.motdMu.Unlock()
	s.log.Printf("motd refreshed: proto=%s version=%s motd=%q", motd.ProtocolVersion, motd.VersionName, motd.Motd)
	return nil
}
