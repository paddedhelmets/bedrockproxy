// Package netherproxy provides NetherNet HTTP signaling and an encrypted ICE
// media relay. The relay rewrites only SDP candidate addresses; identity,
// fingerprints, DTLS, SCTP, and Bedrock payloads remain end-to-end opaque.
// Signaling must be restricted to a trusted LAN: ICE credentials and SDP
// candidates do not authorize arbitrary Internet clients to use this relay.
// Packet limits reduce, but do not prevent, reflection or resource exhaustion.
// Rate limits cannot guarantee availability under UDP floods or spoofing.
// A wildcard MediaBind relies on OS UDP source-address selection, which may
// not match the advertised address on multihomed hosts.
package netherproxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBodySize = 1 << 20
const maxRelays = 256
const maxCandidates = 32
const maxTransactions = 256
const transactionTTL = 40 * time.Second
const maxEarlyChecks = 32
const maxCheckSize = 2048
const maxCandidateLines = 256
const stunRate = 200.0
const stunBurst = 256.0
const unknownRate = 100.0
const unknownBurst = 128.0
const knownRate = 400.0
const knownBurst = 512.0
const fanoutRate = 256.0
const fanoutBurst = 256.0
const nominationReserve = 32.0

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
	remoteIP              net.IP
	mediaBind             string
	clientAdvertiseAddr   net.IP
	upstreamAdvertiseAddr net.IP
	mediaIdleTTL          time.Duration
	client                *http.Client
	log                   *log.Logger

	mu       sync.Mutex
	relays   map[*iceRelay]struct{}
	stopping bool
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
	if cfg.MediaIdleTTL < 0 {
		return nil, errors.New("nethernet: MediaIdleTTL must be positive")
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	host := remote.Hostname()
	remoteAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil || remoteAddr.IP == nil || remoteAddr.IP.To4() == nil {
		return nil, fmt.Errorf("nethernet: cannot resolve remote %q to an IPv4 address: %v", host, err)
	}
	return &Server{
		bindAddr:              cfg.BindAddr,
		remote:                remote,
		remoteIP:              remoteAddr.IP.To4(),
		mediaBind:             cfg.MediaBind,
		clientAdvertiseAddr:   clientAddr,
		upstreamAdvertiseAddr: upstreamAddr,
		mediaIdleTTL:          cfg.MediaIdleTTL,
		client:                cfg.Client,
		log:                   cfg.Logger,
		relays:                make(map[*iceRelay]struct{}),
	}, nil
}

// remapUpstreamCandidates retargets upstream media at the signaling peer's IP.
// A Docker-bridged BDS advertises its container IP, which is unroutable from
// here, but works through matching published ports on the host we reached for
// signaling. Bare-metal upstreams advertise the same IP and are unaffected.
func (s *Server) remapUpstreamCandidates(cands []net.UDPAddr) []net.UDPAddr {
	if len(cands) == 0 {
		return cands
	}
	out := make([]net.UDPAddr, 0, len(cands))
	remapped := make([]string, 0, len(cands))
	for _, c := range cands {
		if !c.IP.Equal(s.remoteIP) {
			remapped = append(remapped, c.String())
			c.IP = s.remoteIP
		}
		out = append(out, c)
	}
	if len(remapped) > 0 {
		s.log.Printf("nethernet: upstream advertised %s; relaying media to %s instead (published port)",
			strings.Join(remapped, ", "), net.JoinHostPort(s.remoteIP.String(), strconv.Itoa(out[0].Port)))
	}
	return out
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
	server := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.closeRelays()
			_ = server.Close()
		case <-done:
		}
	}()
	reapCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.reapRelays(reapCtx)
	s.log.Printf("nethernet signaling/media relay up: %s -> %s", s.bindAddr, s.remote)
	err = server.Serve(listener)
	close(done)
	s.closeRelays()
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

// ServeHTTP forwards the two standard NetherNet signaling endpoints and
// rewrites candidate addresses to the relay's client/upstream interfaces.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
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
	clientUfrag, clientPwd, err := iceCredentials(string(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if s.stopping || len(s.relays) >= maxRelays {
		s.mu.Unlock()
		http.Error(w, "media relay capacity exceeded", http.StatusServiceUnavailable)
		return
	}
	relay, err := newIceRelay(s.mediaBind)
	if err != nil {
		s.mu.Unlock()
		http.Error(w, "media relay unavailable", http.StatusServiceUnavailable)
		return
	}
	s.relays[relay] = struct{}{}
	s.mu.Unlock()
	keep := false
	defer func() {
		if !keep {
			s.removeRelay(relay)
		}
	}()

	offer, clientCandidates, err := rewriteCandidates(string(body), s.upstreamAdvertiseAddr.String(), relay.port())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	relay.configureOffer(clientCandidates, clientUfrag, clientPwd)
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
	upstreamUfrag, upstreamPwd, err := iceCredentials(string(answerBytes))
	if err != nil || upstreamUfrag == clientUfrag {
		http.Error(w, "invalid upstream ICE credentials", http.StatusBadGateway)
		return
	}
	relay.configureAnswer(s.remapUpstreamCandidates(upstreamCandidates), upstreamUfrag, upstreamPwd)
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

func (s *Server) removeRelay(relay *iceRelay) {
	s.mu.Lock()
	delete(s.relays, relay)
	s.mu.Unlock()
	relay.close()
}

func (s *Server) closeRelays() {
	s.mu.Lock()
	s.stopping = true
	all := make([]*iceRelay, 0, len(s.relays))
	for relay := range s.relays {
		delete(s.relays, relay)
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
			for relay := range s.relays {
				if now.Sub(relay.lastSeen()) > s.mediaIdleTTL {
					delete(s.relays, relay)
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
	conn                                               *net.UDPConn
	mu                                                 sync.Mutex
	client                                             *net.UDPAddr
	upstream                                           *net.UDPAddr
	clientCandidates, upstreamCandidates               []net.UDPAddr
	clientUfrag, clientPwd, upstreamUfrag, upstreamPwd string
	nominated                                          bool
	nominationSerial, selectedNomination               uint64
	transactions                                       []iceTransaction
	early                                              []earlyCheck
	stunTokens, fanoutTokens                           float64
	stunRefill, fanoutRefill                           time.Time
	responseTokens                                     float64
	responseRefill                                     time.Time
	knownTokens, unknownTokens                         float64
	knownRefill, unknownRefill                         time.Time
	last                                               time.Time
	closed                                             chan struct{}
	once                                               sync.Once
}

type iceTransaction struct {
	id                    [12]byte
	source, destination   *net.UDPAddr
	fromClient, nominated bool
	created               time.Time
	digest                [32]byte
	serial                uint64
}

type earlyCheck struct {
	packet []byte
	source *net.UDPAddr
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
	now := time.Now()
	r := &iceRelay{conn: conn, last: now, closed: make(chan struct{}), stunTokens: stunBurst, responseTokens: stunBurst, fanoutTokens: fanoutBurst, stunRefill: now, responseRefill: now, fanoutRefill: now, knownTokens: knownBurst, unknownTokens: unknownBurst, knownRefill: now, unknownRefill: now}
	go r.loop()
	return r, nil
}

func (r *iceRelay) port() int { return r.conn.LocalAddr().(*net.UDPAddr).Port }

func (r *iceRelay) configureOffer(client []net.UDPAddr, cu, cp string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clientCandidates = nil
	for i := range client {
		addCandidate(&r.clientCandidates, &client[i])
	}
	r.clientUfrag, r.clientPwd = cu, cp
}

func (r *iceRelay) configureAnswer(upstream []net.UDPAddr, uu, up string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.upstreamCandidates = nil
	for i := range upstream {
		addCandidate(&r.upstreamCandidates, &upstream[i])
	}
	r.upstreamUfrag, r.upstreamPwd = uu, up
	for _, check := range r.early {
		r.handlePacket(check.packet, check.source)
	}
	r.early = nil
}

func (r *iceRelay) configure(client, upstream []net.UDPAddr, cu, cp, uu, up string) {
	r.configureOffer(client, cu, cp)
	r.configureAnswer(upstream, uu, up)
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
		r.mu.Lock()
		r.handlePacket(buf[:n], src)
		r.mu.Unlock()
	}
}

// handlePacket is called with r.mu held. A data path requires a matching
// authenticated response, but that is not proof against a credential holder
// able to spoof the destination address.
func (r *iceRelay) handlePacket(packet []byte, src *net.UDPAddr) {
	now := time.Now()
	if len(packet) >= 20 && binary.BigEndian.Uint32(packet[4:8]) == 0x2112a442 {
		typ := binary.BigEndian.Uint16(packet[:2])
		if typ == 1 {
			if len(packet) > maxCheckSize {
				return
			}
			known := containsCandidate(r.clientCandidates, src) || containsCandidate(r.upstreamCandidates, src)
			if known {
				if !takeTokens(&r.knownTokens, &r.knownRefill, now, knownRate, knownBurst, 1, 0) {
					return
				}
			} else if !takeTokens(&r.unknownTokens, &r.unknownRefill, now, unknownRate, unknownBurst, 1, 0) {
				return
			}
			if r.upstreamPwd == "" {
				// The answer's ufrag is not yet known. Authenticate the password
				// now, then check the complete username before forwarding.
				if len(r.early) < maxEarlyChecks && validICECheck(packet, "", r.clientPwd) && takeTokens(&r.stunTokens, &r.stunRefill, now, stunRate, stunBurst, 1, 0) {
					r.early = append(r.early, earlyCheck{append([]byte(nil), packet...), cloneUDP(src)})
				}
				return
			}
			fromClient := validICECheck(packet, r.upstreamUfrag+":"+r.clientUfrag, r.upstreamPwd)
			fromUpstream := validICECheck(packet, r.clientUfrag+":"+r.upstreamUfrag, r.clientPwd)
			if fromClient == fromUpstream {
				return
			}
			if !takeTokens(&r.stunTokens, &r.stunRefill, now, stunRate, stunBurst, 1, 0) {
				return
			}
			var own *[]net.UDPAddr
			var destinations []net.UDPAddr
			if fromClient {
				own, destinations = &r.clientCandidates, r.upstreamCandidates
			} else {
				own, destinations = &r.upstreamCandidates, r.clientCandidates
			}
			addCandidate(own, src)
			r.pruneTransactions(now)
			var id [12]byte
			copy(id[:], packet[8:20])
			nominated := hasNomination(packet)
			digest := sha256.Sum256(packet)
			var serial uint64
			existing := false
			for _, tx := range r.transactions {
				if tx.id == id && tx.fromClient == fromClient && tx.source.String() == src.String() {
					existing = true
					if tx.digest != digest {
						return
					}
					serial = tx.serial
				}
			}
			if nominated && serial == 0 {
				r.nominationSerial++
				serial = r.nominationSerial
			}
			for i := range destinations {
				dst := &destinations[i]
				if dst.String() == src.String() {
					continue
				}
				found := false
				for _, tx := range r.transactions {
					if tx.id == id && tx.fromClient == fromClient && tx.source.String() == src.String() && tx.destination.String() == dst.String() {
						found = true
						break
					}
				}
				if !found {
					limit := maxTransactions - maxCandidates
					if nominated {
						limit = maxTransactions
					}
					if len(r.transactions) >= limit && nominated && existing {
						continue
					}
				}
				reserve := nominationReserve
				if nominated {
					reserve = 0
				}
				if !takeTokens(&r.fanoutTokens, &r.fanoutRefill, now, fanoutRate, fanoutBurst, 1, reserve) {
					continue
				}
				if !found {
					limit := maxTransactions - maxCandidates
					if nominated {
						limit = maxTransactions
					}
					if len(r.transactions) >= limit && !r.evictTransaction(id, src, fromClient, nominated) {
						continue
					}
					r.transactions = append(r.transactions, iceTransaction{id, cloneUDP(src), cloneUDP(dst), fromClient, nominated, now, digest, serial})
				}
				_, _ = r.conn.WriteToUDP(packet, dst)
			}
			r.last = now
			return
		}
		if typ == 0x0101 || typ == 0x0111 {
			r.pruneTransactions(now)
			for i, tx := range r.transactions {
				if len(packet) < 20 || string(tx.id[:]) != string(packet[8:20]) || tx.destination.String() != src.String() {
					continue
				}
				password := r.clientPwd
				if tx.fromClient {
					password = r.upstreamPwd
				}
				if !validSTUNIntegrity(packet, typ, "", password, false) {
					continue
				}
				if typ == 0x0101 && !hasMappedAddress(packet) {
					continue
				}
				if !takeTokens(&r.responseTokens, &r.responseRefill, now, stunRate, stunBurst, 1, 0) {
					return
				}
				if typ == 0x0101 && (!r.nominated || (tx.nominated && tx.serial > r.selectedNomination)) {
					if tx.fromClient {
						r.client, r.upstream = cloneUDP(tx.source), cloneUDP(src)
					} else {
						r.client, r.upstream = cloneUDP(src), cloneUDP(tx.source)
					}
					if tx.nominated {
						r.nominated = true
						r.selectedNomination = tx.serial
					}
				}
				_, _ = r.conn.WriteToUDP(packet, tx.source)
				copy(r.transactions[i:], r.transactions[i+1:])
				r.transactions = r.transactions[:len(r.transactions)-1]
				r.last = now
				return
			}
			return
		}
	}
	if r.client != nil && r.upstream != nil {
		if src.String() == r.client.String() {
			_, _ = r.conn.WriteToUDP(packet, r.upstream)
			r.last = now
		} else if src.String() == r.upstream.String() {
			_, _ = r.conn.WriteToUDP(packet, r.client)
			r.last = now
		}
	}
}

// Prefer evicting ordinary work. Preserve at least one full nomination's
// worth of entries when ordinary checks must displace nomination traffic.
func (r *iceRelay) evictTransaction(id [12]byte, src *net.UDPAddr, fromClient, allowNomination bool) bool {
	oldest := -1
	nominationCount := 0
	for i, tx := range r.transactions {
		if tx.nominated {
			nominationCount++
		}
		if tx.nominated && !allowNomination {
			continue
		}
		if tx.id == id && tx.fromClient == fromClient && tx.source.String() == src.String() {
			continue
		}
		if oldest < 0 || (r.transactions[oldest].nominated && !tx.nominated) ||
			(r.transactions[oldest].nominated == tx.nominated && tx.created.Before(r.transactions[oldest].created)) {
			oldest = i
		}
	}
	if oldest < 0 && !allowNomination && nominationCount > maxCandidates {
		for i, tx := range r.transactions {
			if !tx.nominated || (tx.id == id && tx.fromClient == fromClient && tx.source.String() == src.String()) {
				continue
			}
			if oldest < 0 || tx.created.Before(r.transactions[oldest].created) {
				oldest = i
			}
		}
	}
	if oldest < 0 {
		return false
	}
	copy(r.transactions[oldest:], r.transactions[oldest+1:])
	r.transactions = r.transactions[:len(r.transactions)-1]
	return true
}

func containsCandidate(candidates []net.UDPAddr, addr *net.UDPAddr) bool {
	for _, candidate := range candidates {
		if candidate.String() == addr.String() {
			return true
		}
	}
	return false
}

func takeTokens(tokens *float64, last *time.Time, now time.Time, rate, burst, cost, reserve float64) bool {
	if now.After(*last) {
		*tokens += now.Sub(*last).Seconds() * rate
		if *tokens > burst {
			*tokens = burst
		}
		*last = now
	}
	if *tokens < cost+reserve {
		return false
	}
	*tokens -= cost
	return true
}

func addCandidate(candidates *[]net.UDPAddr, addr *net.UDPAddr) {
	for _, candidate := range *candidates {
		if candidate.String() == addr.String() {
			return
		}
	}
	if len(*candidates) < maxCandidates {
		*candidates = append(*candidates, *cloneUDP(addr))
	}
}

func (r *iceRelay) pruneTransactions(now time.Time) {
	kept := r.transactions[:0]
	for _, tx := range r.transactions {
		if now.Sub(tx.created) < transactionTTL {
			kept = append(kept, tx)
		}
	}
	r.transactions = kept
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

// This relay supports a single ICE credential pair per SDP, not unbundled
// media sections with distinct ICE transports.
func iceCredentials(sdp string) (string, string, error) {
	var ufrag, pwd string
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		var dst *string
		var value string
		switch {
		case strings.HasPrefix(line, "a=ice-ufrag:"):
			dst, value = &ufrag, strings.TrimPrefix(line, "a=ice-ufrag:")
		case strings.HasPrefix(line, "a=ice-pwd:"):
			dst, value = &pwd, strings.TrimPrefix(line, "a=ice-pwd:")
		default:
			continue
		}
		if value == "" || strings.ContainsAny(value, " \t:\r\n") || (*dst != "" && *dst != value) {
			return "", "", errors.New("invalid or multiple ICE credentials")
		}
		*dst = value
	}
	if ufrag == "" || pwd == "" {
		return "", "", errors.New("missing ICE credentials")
	}
	return ufrag, pwd, nil
}

// RFC 8445 ICE checks use the receiver's password and USERNAME in
// receiver:sender order. RFC 8489 computes HMAC through the attribute
// preceding MESSAGE-INTEGRITY, with the header length adjusted to include it.
func validICECheck(packet []byte, username, password string) bool {
	return validSTUNIntegrity(packet, 1, username, password, true)
}

func validSTUNIntegrity(packet []byte, messageType uint16, username, password string, requireUser bool) bool {
	if password == "" || len(packet) < 20 || binary.BigEndian.Uint16(packet[:2]) != messageType ||
		binary.BigEndian.Uint32(packet[4:8]) != 0x2112a442 ||
		int(binary.BigEndian.Uint16(packet[2:4])) != len(packet)-20 || len(packet)%4 != 0 {
		return false
	}
	seenUser, seenIntegrity := false, false
	valid := false
	for pos := 20; pos < len(packet); {
		if pos+4 > len(packet) {
			return false
		}
		typ, size := binary.BigEndian.Uint16(packet[pos:]), int(binary.BigEndian.Uint16(packet[pos+2:]))
		end := pos + 4 + size
		next := pos + 4 + (size+3)&^3
		if end > len(packet) || next > len(packet) {
			return false
		}
		switch typ {
		case 0x0006:
			if seenUser || seenIntegrity || size == 0 || (username != "" && string(packet[pos+4:end]) != username) {
				return false
			}
			seenUser = true
		case 0x0008:
			if seenIntegrity || (requireUser && !seenUser) || size != sha1.Size {
				return false
			}
			seenIntegrity = true
			header := append([]byte(nil), packet[:20]...)
			binary.BigEndian.PutUint16(header[2:4], uint16(end-20))
			mac := hmac.New(sha1.New, []byte(password))
			_, _ = mac.Write(header)
			_, _ = mac.Write(packet[20:pos])
			valid = hmac.Equal(mac.Sum(nil), packet[pos+4:end])
		}
		pos = next
	}
	return seenIntegrity && valid
}

func hasNomination(packet []byte) bool {
	use, controlling := false, false
	for pos := 20; pos+4 <= len(packet); {
		typ, size := binary.BigEndian.Uint16(packet[pos:]), int(binary.BigEndian.Uint16(packet[pos+2:]))
		next := pos + 4 + (size+3)&^3
		if next > len(packet) || typ == 8 {
			break
		}
		if typ == 0x0025 && size == 0 {
			use = true
		}
		if typ == 0x802a && size == 8 {
			controlling = true
		}
		pos = next
	}
	return use && controlling
}

func hasMappedAddress(packet []byte) bool {
	for pos := 20; pos+4 <= len(packet); {
		typ, size := binary.BigEndian.Uint16(packet[pos:]), int(binary.BigEndian.Uint16(packet[pos+2:]))
		next := pos + 4 + (size+3)&^3
		if next > len(packet) || typ == 8 {
			break
		}
		if typ == 0x0020 && ((size == 8 && packet[pos+5] == 1) || (size == 20 && packet[pos+5] == 2)) {
			return true
		}
		pos = next
	}
	return false
}

func rewriteCandidates(sdp, address string, port int) (string, []net.UDPAddr, error) {
	lines := strings.SplitAfter(sdp, "\n")
	var candidates []net.UDPAddr
	count := 0
	seen := make(map[string]struct{})
	candidateLines := 0
	for i, raw := range lines {
		line := strings.TrimSuffix(strings.TrimSuffix(raw, "\n"), "\r")
		if !strings.HasPrefix(line, "a=candidate:") {
			continue
		}
		candidateLines++
		if candidateLines > maxCandidateLines {
			return "", nil, errors.New("too many ICE candidate lines")
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			lines[i] = ""
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
		candidate := net.UDPAddr{IP: ip.To4(), Port: candidatePort}
		if _, ok := seen[candidate.String()]; !ok {
			seen[candidate.String()] = struct{}{}
			candidates = append(candidates, candidate)
			if len(candidates) > maxCandidates {
				return "", nil, errors.New("too many ICE candidates")
			}
		}
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
