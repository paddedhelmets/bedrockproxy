// Package netherproxy provides NetherNet HTTP signaling and an encrypted ICE
// media relay. The relay rewrites only SDP candidate addresses; identity,
// fingerprints, DTLS, SCTP, and Bedrock payloads remain end-to-end opaque.
package netherproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBodySize = 1 << 20

// Config controls a NetherNet signaling and ICE relay.
type Config struct {
	BindAddr              string
	RemoteURL             string
	MediaBind             string
	ClientAdvertiseAddr   string
	UpstreamAdvertiseAddr string
	MediaIdleTTL          time.Duration
	Client                *http.Client
	Logger                *log.Logger
}

// Server relays signaling and forwards encrypted WebRTC UDP packets.
type Server struct {
	bindAddr              string
	remote                *url.URL
	mediaBind             string
	clientAdvertiseAddr   net.IP
	upstreamAdvertiseAddr net.IP
	mediaIdleTTL          time.Duration
	client                *http.Client
	log                   *log.Logger

	mu     sync.Mutex
	relays map[string]*iceRelay
}

// New validates configuration and returns a signaling/media relay. A bare
// host:port is accepted as a convenience and is interpreted as plain HTTP.
func New(cfg Config) (*Server, error) {
	if cfg.BindAddr == "" {
		cfg.BindAddr = ":19132"
	}
	if cfg.MediaBind == "" {
		cfg.MediaBind = ":0"
	}
	if cfg.RemoteURL == "" {
		return nil, errors.New("nethernet: RemoteURL is required")
	}
	remoteText := cfg.RemoteURL
	if !strings.Contains(remoteText, "://") {
		remoteText = "http://" + remoteText
	}
	remote, err := url.Parse(remoteText)
	if err != nil || remote.Host == "" || (remote.Scheme != "http" && remote.Scheme != "https") {
		return nil, fmt.Errorf("nethernet: invalid RemoteURL %q", cfg.RemoteURL)
	}
	clientAddr, err := parseIPv4(cfg.ClientAdvertiseAddr, "ClientAdvertiseAddr")
	if err != nil {
		return nil, err
	}
	upstreamAddr, err := parseIPv4(cfg.UpstreamAdvertiseAddr, "UpstreamAdvertiseAddr")
	if err != nil {
		return nil, err
	}
	if cfg.MediaIdleTTL == 0 {
		cfg.MediaIdleTTL = 5 * time.Minute
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	return &Server{
		bindAddr:              cfg.BindAddr,
		remote:                remote,
		mediaBind:             cfg.MediaBind,
		clientAdvertiseAddr:   clientAddr,
		upstreamAdvertiseAddr: upstreamAddr,
		mediaIdleTTL:          cfg.MediaIdleTTL,
		client:                cfg.Client,
		log:                   cfg.Logger,
		relays:                make(map[string]*iceRelay),
	}, nil
}

func parseIPv4(value, name string) (net.IP, error) {
	if value == "" {
		return nil, fmt.Errorf("nethernet: %s is required for media relay", name)
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("nethernet: %s must be an IPv4 address", name)
	}
	return ip.To4(), nil
}

// Serve runs the TCP signaling relay and UDP media relays until ctx is
// cancelled or the listener fails.
func (s *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.bindAddr)
	if err != nil {
		return fmt.Errorf("nethernet: listen %s: %w", s.bindAddr, err)
	}
	server := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
		s.closeRelays()
	}()
	go s.reapRelays(ctx)
	s.log.Printf("nethernet signaling/media relay up: %s -> %s", s.bindAddr, s.remote)
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

// ServeHTTP forwards the two standard NetherNet signaling endpoints and
// rewrites candidate addresses to the relay's client/upstream interfaces.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !validPath(r.Method, r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		s.forwardStatus(w, r)
		return
	}
	s.handleOffer(w, r)
}

func (s *Server) forwardStatus(w http.ResponseWriter, r *http.Request) {
	resp, err := s.upstreamRequest(r, r.Body)
	if err != nil {
		s.log.Printf("nethernet status upstream: %v", err)
		http.Error(w, "upstream signaling unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	s.copyResponse(w, resp)
}

func (s *Server) handleOffer(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil || len(body) > maxBodySize {
		http.Error(w, "SDP offer too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	relay, err := newIceRelay(s.mediaBind)
	if err != nil {
		http.Error(w, "media relay unavailable", http.StatusServiceUnavailable)
		return
	}
	key := r.URL.Path
	s.mu.Lock()
	if old := s.relays[key]; old != nil {
		old.close()
	}
	s.relays[key] = relay
	s.mu.Unlock()
	keep := false
	defer func() {
		if !keep {
			s.removeRelay(key, relay)
		}
	}()

	offer, clientCandidates, err := rewriteCandidates(string(body), s.upstreamAdvertiseAddr.String(), relay.port())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = clientCandidates // The relay learns the client address from the first packet.
	resp, err := s.upstreamRequest(r, strings.NewReader(offer))
	if err != nil {
		s.log.Printf("nethernet offer upstream: %v", err)
		http.Error(w, "upstream signaling unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	answerBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if readErr != nil || len(answerBytes) > maxBodySize {
		http.Error(w, "upstream SDP answer too large or unreadable", http.StatusBadGateway)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		copyResponseBody(w, resp.StatusCode, resp.Header.Get("Content-Type"), answerBytes)
		return
	}
	if _, err := strconv.ParseUint(strings.TrimSpace(string(answerBytes)), 10, 32); err == nil {
		copyResponseBody(w, resp.StatusCode, resp.Header.Get("Content-Type"), answerBytes)
		return
	}
	answer, upstreamCandidates, err := rewriteCandidates(string(answerBytes), s.clientAdvertiseAddr.String(), relay.port())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	relay.setUpstream(upstreamCandidates)
	keep = true
	w.Header().Set("Content-Type", "application/sdp")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, answer)
}

func (s *Server) upstreamRequest(r *http.Request, body io.Reader) (*http.Response, error) {
	target := *s.remote
	target.Path = joinRemotePath(s.remote.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"Accept", "Content-Type", "User-Agent"} {
		if value := r.Header.Get(name); value != "" {
			req.Header.Set(name, value)
		}
	}
	return s.client.Do(req)
}

func (s *Server) copyResponse(w http.ResponseWriter, resp *http.Response) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil || len(body) > maxBodySize {
		http.Error(w, "upstream response too large or unreadable", http.StatusBadGateway)
		return
	}
	copyResponseBody(w, resp.StatusCode, resp.Header.Get("Content-Type"), body)
}

func copyResponseBody(w http.ResponseWriter, status int, contentType string, body []byte) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) removeRelay(key string, relay *iceRelay) {
	s.mu.Lock()
	if s.relays[key] == relay {
		delete(s.relays, key)
	}
	s.mu.Unlock()
	relay.close()
}

func (s *Server) closeRelays() {
	s.mu.Lock()
	all := make([]*iceRelay, 0, len(s.relays))
	for key, relay := range s.relays {
		delete(s.relays, key)
		all = append(all, relay)
	}
	s.mu.Unlock()
	for _, relay := range all {
		relay.close()
	}
}

func (s *Server) reapRelays(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			var dead []*iceRelay
			for key, relay := range s.relays {
				if now.Sub(relay.lastSeen()) > s.mediaIdleTTL {
					delete(s.relays, key)
					dead = append(dead, relay)
				}
			}
			s.mu.Unlock()
			for _, relay := range dead {
				relay.close()
			}
		}
	}
}

type iceRelay struct {
	conn     *net.UDPConn
	mu       sync.Mutex
	client   *net.UDPAddr
	upstream map[string]*net.UDPAddr
	last     time.Time
	closed   chan struct{}
	once     sync.Once
}

func newIceRelay(bind string) (*iceRelay, error) {
	addr, err := net.ResolveUDPAddr("udp4", bind)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}
	r := &iceRelay{conn: conn, upstream: make(map[string]*net.UDPAddr), last: time.Now(), closed: make(chan struct{})}
	go r.loop()
	return r, nil
}

func (r *iceRelay) port() int { return r.conn.LocalAddr().(*net.UDPAddr).Port }

func (r *iceRelay) setUpstream(addrs []net.UDPAddr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, addr := range addrs {
		copyAddr := addr
		r.upstream[addr.String()] = &copyAddr
	}
}

func (r *iceRelay) lastSeen() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

func (r *iceRelay) loop() {
	buf := make([]byte, 65535)
	for {
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-r.closed:
				return
			default:
				return
			}
		}
		packet := slices.Clone(buf[:n])
		r.mu.Lock()
		r.last = time.Now()
		_, fromUpstream := r.upstream[src.String()]
		client := cloneUDP(r.client)
		if fromUpstream {
			if client != nil {
				_, _ = r.conn.WriteToUDP(packet, client)
			}
		} else {
			r.client = cloneUDP(src)
			for _, upstream := range r.upstream {
				_, _ = r.conn.WriteToUDP(packet, upstream)
			}
		}
		r.mu.Unlock()
	}
}

func (r *iceRelay) close() {
	r.once.Do(func() {
		close(r.closed)
		_ = r.conn.Close()
	})
}

func cloneUDP(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	copyAddr := *addr
	copyAddr.IP = append(net.IP(nil), addr.IP...)
	return &copyAddr
}

func rewriteCandidates(sdp, address string, port int) (string, []net.UDPAddr, error) {
	lines := strings.SplitAfter(sdp, "\n")
	var candidates []net.UDPAddr
	count := 0
	for i, raw := range lines {
		line := strings.TrimSuffix(strings.TrimSuffix(raw, "\n"), "\r")
		if !strings.HasPrefix(line, "a=candidate:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		ip := net.ParseIP(fields[4])
		candidatePort, err := strconv.Atoi(fields[5])
		if err != nil || ip == nil || ip.To4() == nil || candidatePort < 1 || candidatePort > 65535 || strings.ToLower(fields[2]) != "udp" {
			// This first relay is IPv4/UDP by design. Keep usable IPv4 UDP
			// candidates while discarding IPv6/TCP candidates that this socket
			// cannot forward.
			lines[i] = ""
			continue
		}
		candidates = append(candidates, net.UDPAddr{IP: ip.To4(), Port: candidatePort})
		fields[4] = address
		fields[5] = strconv.Itoa(port)
		for j, field := range fields {
			if field == "typ" && j+1 < len(fields) {
				fields[j+1] = "host"
			}
		}
		newLine := strings.Join(fields, " ")
		if strings.HasSuffix(raw, "\r\n") {
			newLine += "\r\n"
		} else if strings.HasSuffix(raw, "\n") {
			newLine += "\n"
		}
		lines[i] = newLine
		count++
	}
	if count == 0 {
		return "", nil, errors.New("SDP contains no ICE candidates")
	}
	return strings.Join(lines, ""), candidates, nil
}

func validPath(method, requestPath string) bool {
	if method == http.MethodGet {
		return requestPath == "/v1/join"
	}
	return method == http.MethodPost && strings.HasPrefix(requestPath, "/v1/join/") &&
		path.Base(requestPath) != "join" && !strings.Contains(path.Base(requestPath), "/")
}

func joinRemotePath(base, requestPath string) string {
	base = strings.TrimSuffix(base, "/")
	if base == "" {
		return requestPath
	}
	return base + requestPath
}
