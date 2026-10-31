package proxy

// NetherNet relay (Bedrock 26.50+ transport; the only one 26.60+ clients speak).
//
// A console that resolves a featured server to us signals over plain HTTP on TCP
// <bind port>. We forward that to the remote's signaling endpoint, rewriting the
// ICE candidates so that:
//
//   - the server is told the client's only candidate is a per-session upstream
//     UDP socket on this proxy, and
//   - the console is told the server's only candidate is our LAN UDP socket
//     (the same one the RakNet relay uses).
//
// The console's first STUN connectivity check carries USERNAME
// "<server ufrag>:<client ufrag>", which identifies the session; from then on that
// console address is relayed to the server's media port and back. DTLS/SCTP stay
// end-to-end, so the server's auth and identity checks are unaffected. See
// package nethernet for the protocol notes.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/paddedhelmets/bedrockproxy/nethernet"
	"github.com/paddedhelmets/bedrockproxy/raknet"
)

const (
	maxSDPBytes     = 64 << 10
	nnPendingTTL    = 60 * time.Second // offer answered but console never showed up
	signalTimeout   = 15 * time.Second
	joinInfoPath    = "/v1/join"
	joinSignalPrefx = "/v1/join/"
)

// nnSession is one console<->server NetherNet media relay.
type nnSession struct {
	key      string                      // "<server ufrag>:<client ufrag>"
	upstream *net.UDPConn                // our socket the server sees as the client
	media    *net.UDPAddr                // server's media candidate (remote IP, advertised port)
	console  atomic.Pointer[net.UDPAddr] // nil until the first STUN check arrives
	lastSeen atomic.Int64                // unix nanos
	created  time.Time
}

func (n *nnSession) touch() { n.lastSeen.Store(time.Now().UnixNano()) }

// serveSignaling runs the HTTP signaling relay on TCP until ctx is cancelled.
func (s *Server) serveSignaling(ctx context.Context) error {
	hs := &http.Server{
		Handler:           http.HandlerFunc(s.handleSignal),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          s.log,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	s.log.Printf("nethernet signaling relay: tcp %s -> http://%s", s.cfg.BindAddr, s.cfg.RemoteAddr)
	if err := hs.Serve(s.tcp); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// handleSignal relays one signaling request to the remote.
func (s *Server) handleSignal(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxSDPBytes))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var sess *nnSession
	isOffer := r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, joinSignalPrefx)
	offer := nethernet.Parse(string(body))
	if isOffer {
		if offer.Ufrag == "" {
			s.log.Printf("nethernet: offer from %s has no ice-ufrag; relaying unmodified", r.RemoteAddr)
		} else {
			sess, err = s.newNNSession()
			if err != nil {
				s.log.Printf("nethernet: upstream socket for %s: %v", r.RemoteAddr, err)
				http.Error(w, "proxy error", http.StatusBadGateway)
				return
			}
			up := sess.upstream.LocalAddr().(*net.UDPAddr)
			body = []byte(nethernet.RewriteCandidates(string(body), up.IP, up.Port))
		}
	}

	resp, err := s.forwardSignal(r, body)
	if err != nil {
		s.log.Printf("nethernet: %s %s from %s: %v", r.Method, r.URL.Path, r.RemoteAddr, err)
		if sess != nil {
			_ = sess.upstream.Close()
		}
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxSDPBytes))
	if err != nil {
		if sess != nil {
			_ = sess.upstream.Close()
		}
		http.Error(w, "upstream read", http.StatusBadGateway)
		return
	}

	ok2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	switch {
	case sess != nil && ok2xx && nethernet.Parse(string(out)).Ufrag == "":
		// BDS refuses an offer with 200 and a bare error code (e.g. "37") as the
		// body; hand that to the console untouched so it shows the real error.
		s.log.Printf("nethernet: server refused offer from %s: %q", r.RemoteAddr, bytes.TrimSpace(out))
		_ = sess.upstream.Close()
	case sess != nil && ok2xx:
		out, err = s.acceptAnswer(r, sess, offer.Ufrag, out)
		if err != nil {
			s.log.Printf("nethernet: answer for %s: %v", r.RemoteAddr, err)
			_ = sess.upstream.Close()
			http.Error(w, "bad upstream answer", http.StatusBadGateway)
			return
		}
	case sess != nil:
		s.log.Printf("nethernet: server rejected offer from %s: %s %s", r.RemoteAddr, resp.Status, bytes.TrimSpace(out))
		_ = sess.upstream.Close()
	case r.Method == http.MethodGet && r.URL.Path == joinInfoPath && ok2xx && s.cfg.Motd != "":
		out = overrideJoinName(out, s.cfg.Motd)
	}

	for k, vs := range resp.Header {
		if k == "Content-Length" || k == "Connection" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
}

// forwardSignal sends r (with body) to the remote's signaling endpoint.
func (s *Server) forwardSignal(r *http.Request, body []byte) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(r.Context(), signalTimeout)
	url := "http://" + s.cfg.RemoteAddr + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(ctx, r.Method, url, bytes.NewReader(body))
	if err != nil {
		cancel()
		return nil, err
	}
	for k, vs := range r.Header {
		switch k {
		case "Content-Length", "Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade":
			continue
		}
		req.Header[k] = vs
	}
	resp, err := s.http.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = cancelOnClose{resp.Body, cancel}
	return resp, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error { err := c.ReadCloser.Close(); c.cancel(); return err }

// acceptAnswer registers sess from the server's SDP answer and returns the
// answer rewritten to point the console at our LAN UDP socket.
func (s *Server) acceptAnswer(r *http.Request, sess *nnSession, clientUfrag string, answer []byte) ([]byte, error) {
	ans := nethernet.Parse(string(answer))
	if ans.Ufrag == "" {
		return nil, errors.New("answer has no ice-ufrag")
	}
	cand, ok := nethernet.PickUDPv4(ans.Candidates, s.remote.IP)
	if !ok {
		return nil, errors.New("answer has no UDP IPv4 candidate")
	}
	// Always send media to the remote's IP as we reach it: a server in a Docker
	// bridge advertises its container IP, which is unreachable from here but
	// works through a matching published port.
	sess.media = &net.UDPAddr{IP: s.remote.IP, Port: cand.Port}
	if cand.IP != s.remote.IP.String() {
		s.log.Printf("nethernet: server advertised %s:%d; relaying media to %s instead", cand.IP, cand.Port, sess.media)
	}

	// The console reached us on this IP, so that's what it can send UDP to.
	lanIP := s.lanIPFor(r)
	lanPort := s.conn.LocalAddr().(*net.UDPAddr).Port
	sess.key = ans.Ufrag + ":" + clientUfrag

	s.nnMu.Lock()
	s.nnSessions[sess.key] = sess
	s.nnMu.Unlock()
	go s.nnDownstream(sess)

	s.log.Printf("nethernet: session %s offered by %s: console -> %s:%d -> %s via %s",
		sess.key, r.RemoteAddr, lanIP, lanPort, sess.media, sess.upstream.LocalAddr())
	return []byte(nethernet.RewriteCandidates(string(answer), lanIP, lanPort)), nil
}

// lanIPFor returns our IP on the connection the console used for signaling.
func (s *Server) lanIPFor(r *http.Request) net.IP {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok && a.IP.To4() != nil {
		return a.IP.To4()
	}
	if la := s.conn.LocalAddr().(*net.UDPAddr); la.IP != nil && !la.IP.IsUnspecified() {
		return la.IP
	}
	return net.IPv4(127, 0, 0, 1)
}

// newNNSession opens an upstream UDP socket on the interface that reaches the
// remote, so the candidate we hand the server is one it can actually reach.
func (s *Server) newNNSession() (*nnSession, error) {
	probe, err := net.DialUDP("udp4", nil, s.remote)
	if err != nil {
		return nil, err
	}
	local := probe.LocalAddr().(*net.UDPAddr).IP
	_ = probe.Close()
	up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local})
	if err != nil {
		return nil, err
	}
	sess := &nnSession{upstream: up, created: time.Now()}
	sess.touch()
	return sess, nil
}

// handleNetherNet routes a LAN datagram that belongs to a NetherNet session.
// It reports whether b was consumed (so it must not go to the RakNet relay).
func (s *Server) handleNetherNet(b []byte, console *net.UDPAddr) bool {
	key := console.String()
	s.nnMu.Lock()
	sess := s.nnByConsole[key]
	if sess == nil {
		user, isSTUN := nethernet.STUNUsername(b)
		if !isSTUN {
			s.nnMu.Unlock()
			return nethernet.IsSTUN(b) // keyless STUN: drop; anything else: RakNet
		}
		sess = s.nnSessions[user]
		if sess == nil {
			s.nnMu.Unlock()
			return true // check for a session we don't know (stale/expired)
		}
		s.nnByConsole[key] = sess
		if sess.console.Swap(console) == nil {
			s.log.Printf("nethernet: session %s bound to console %s", sess.key, console)
		}
	}
	s.nnMu.Unlock()

	sess.console.Store(console)
	sess.touch()
	if _, err := sess.upstream.WriteToUDP(b, sess.media); err != nil {
		s.log.Printf("nethernet: upstream write for %s: %v", console, err)
	}
	return true
}

// nnDownstream pumps server->console media for one session until it's closed.
func (s *Server) nnDownstream(sess *nnSession) {
	buf := make([]byte, mtu)
	for {
		n, from, err := sess.upstream.ReadFromUDP(buf)
		if err != nil {
			s.closeNNSession(sess)
			return
		}
		if !from.IP.Equal(s.remote.IP) {
			continue
		}
		c := sess.console.Load()
		if c == nil {
			continue // server checks before the console's first check; ICE retries
		}
		sess.touch()
		if _, err := s.conn.WriteToUDP(buf[:n], c); err != nil {
			s.log.Printf("nethernet: downstream write to %s: %v", c, err)
		}
	}
}

// closeNNSession removes sess from both indexes and closes its socket once.
func (s *Server) closeNNSession(sess *nnSession) {
	s.nnMu.Lock()
	_, ok := s.nnSessions[sess.key]
	delete(s.nnSessions, sess.key)
	for k, v := range s.nnByConsole {
		if v == sess {
			delete(s.nnByConsole, k)
		}
	}
	s.nnMu.Unlock()
	_ = sess.upstream.Close()
	if ok {
		s.log.Printf("nethernet: session %s closed", sess.key)
	}
}

// reapNetherNet closes sessions that never bound or have gone idle.
func (s *Server) reapNetherNet() {
	now := time.Now()
	var dead []*nnSession
	s.nnMu.Lock()
	for _, sess := range s.nnSessions {
		idle := now.Sub(time.Unix(0, sess.lastSeen.Load()))
		if (sess.console.Load() == nil && now.Sub(sess.created) > nnPendingTTL) || idle > s.cfg.SessionIdleTTL {
			dead = append(dead, sess)
		}
	}
	s.nnMu.Unlock()
	for _, sess := range dead {
		s.closeNNSession(sess)
	}
}

// joinInfo is the GET /v1/join response body.
type joinInfo struct {
	Name       string `json:"name"`
	Protocol   int    `json:"protocol"`
	Version    string `json:"version"`
	Level      string `json:"level"`
	Players    int    `json:"players"`
	MaxPlayers int    `json:"maxPlayers"`
	GameType   int    `json:"gameType"`
}

// overrideJoinName replaces the server name in a GET /v1/join body.
func overrideJoinName(body []byte, name string) []byte {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	m["name"] = name
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// probeJoinInfo fetches the remote's NetherNet server info as a RakNet-style
// MOTD, for NetherNet-only servers that no longer answer RakNet pings.
func (s *Server) probeJoinInfo() (*raknet.Motd, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+s.cfg.RemoteAddr+joinInfoPath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", joinInfoPath, resp.Status)
	}
	var info joinInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSDPBytes)).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode %s: %w", joinInfoPath, err)
	}
	m := raknet.DefaultMotd(s.serverID)
	m.Motd = info.Name
	m.SubMotd = info.Level
	m.ProtocolVersion = strconv.Itoa(info.Protocol)
	m.VersionName = info.Version
	m.PlayerCount = strconv.Itoa(info.Players)
	m.MaxPlayers = strconv.Itoa(info.MaxPlayers)
	return m, nil
}
