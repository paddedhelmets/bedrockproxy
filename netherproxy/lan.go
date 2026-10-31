package netherproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
)

// LANConfig configures the experimental LAN discovery/signaling bridge. Data
// must describe the actual upstream, including its authentication policy and
// nonce. The HTTP status endpoint does not provide those fields.
type LANConfig struct {
	BindAddr      string
	NetworkID     uint64
	Data          discovery.ServerData
	QuietWindow   time.Duration
	GatherTimeout time.Duration
}

// LANBridge advertises one upstream and translates LAN signaling into calls
// to relay. It does not terminate WebRTC or generate an identity assertion.
// Only use on a trusted LAN: discovery's shared wire key is not authentication.
type LANBridge struct {
	listener      *discovery.Listener
	relay         http.Handler
	quiet, gather time.Duration
	ctx           context.Context
	cancel        context.CancelFunc
	stop          func()
	mu            sync.Mutex
	pending       map[lanKey]*lanExchange
	early         map[lanKey][]string
	wg            sync.WaitGroup
	closed        bool
}

type lanKey struct {
	network    string
	connection uint64
}

// lanExchange carries the state of one offer negotiation: its trickled
// candidates and a context canceled when the bridge closes or the client
// cancels the negotiation with SignalTypeError.
type lanExchange struct {
	candidates chan string
	ctx        context.Context
	cancel     context.CancelFunc
}

const (
	// maxLANNegotiations bounds concurrent offer negotiations.
	maxLANNegotiations = 64
	// maxLANEarlyCandidates bounds candidates buffered per connection before
	// their offer arrives, like go-nethernet's deferred signal bound.
	maxLANEarlyCandidates = 32
)

// errLANNoCandidates reports an offer that reached the hard gathering
// deadline without a usable candidate. It maps to a negotiation-timeout code.
var errLANNoCandidates = errors.New("LAN offer has no candidates")

// NewLANBridge starts discovery immediately. relay should be the existing
// *Server, whose Serve method must also run to reap idle media relays.
// Close the bridge before stopping the relay. NetworkID zero chooses a random ID.
func NewLANBridge(cfg LANConfig, relay http.Handler) (*LANBridge, error) {
	if relay == nil {
		return nil, errors.New("nethernet LAN: relay is required")
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = ":7551"
	}
	if cfg.QuietWindow == 0 {
		cfg.QuietWindow = 500 * time.Millisecond
	}
	if cfg.GatherTimeout == 0 {
		cfg.GatherTimeout = 5 * time.Second
	}
	if cfg.QuietWindow < 0 || cfg.GatherTimeout < cfg.QuietWindow || cfg.GatherTimeout > 20*time.Second {
		return nil, errors.New("nethernet LAN: invalid gather durations")
	}
	if cfg.Data.ConnectionType != 4 || (!cfg.Data.AcceptsOnlineAuth && !cfg.Data.AcceptsSelfSignedAuth) || cfg.Data.Protocol <= 0 || cfg.Data.Version == "" {
		return nil, errors.New("nethernet LAN: supply protocol, version, authentication policy and connection type 4")
	}
	data, err := cfg.Data.MarshalBinary()
	if err != nil || len(data) > 4096 {
		return nil, errors.New("nethernet LAN: invalid or oversized discovery data")
	}
	l, err := (discovery.ListenConfig{NetworkID: cfg.NetworkID}).Listen(cfg.BindAddr)
	if err != nil {
		return nil, err
	}
	l.ServerData(&cfg.Data)
	ctx, cancel := context.WithCancel(context.Background())
	b := &LANBridge{listener: l, relay: relay, quiet: cfg.QuietWindow, gather: cfg.GatherTimeout, ctx: ctx, cancel: cancel, pending: make(map[lanKey]*lanExchange), early: make(map[lanKey][]string)}
	b.stop = l.Notify(b)
	return b, nil
}

// NetworkID is this discovery listener's decimal network ID, not the upstream's identity.
func (b *LANBridge) NetworkID() string { return b.listener.NetworkID() }

// NotifySignal accepts bounded concurrent offers, candidate signals and
// remote cancellation errors without blocking the discovery listener.
// Candidates arriving before their offer are buffered up to a per-connection
// bound and replayed when the offer arrives, as go-nethernet's listener
// defers early signals. Candidates arriving after a negotiation ended, beyond
// the buffer, or after queue overflow cannot be forwarded. SignalTypeError
// from the client cancels its pending negotiation, freeing the slot and
// aborting any in-flight relay request.
func (b *LANBridge) NotifySignal(s *nethernet.Signal) bool {
	if s == nil || len(s.Data) > maxBodySize {
		return false
	}
	if _, err := strconv.ParseUint(s.NetworkID, 10, 64); err != nil {
		return false
	}
	k := lanKey{s.NetworkID, s.ConnectionID}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	switch s.Type {
	case nethernet.SignalTypeOffer:
		if _, exists := b.pending[k]; exists || len(b.pending) >= maxLANNegotiations {
			return false
		}
		e := &lanExchange{candidates: make(chan string, 64)}
		e.ctx, e.cancel = context.WithCancel(b.ctx)
		// The channel holds at least maxLANEarlyCandidates, so replaying the
		// buffered candidates can never block while holding the lock.
		for _, c := range b.early[k] {
			e.candidates <- c
		}
		delete(b.early, k)
		b.pending[k] = e
		b.wg.Add(1)
		go b.offer(k, e, s.Data)
		return true
	case nethernet.SignalTypeCandidate:
		if e := b.pending[k]; e != nil {
			select {
			case e.candidates <- s.Data:
				return true
			default:
				return false
			}
		}
		if len(b.early[k]) >= maxLANEarlyCandidates || (len(b.early[k]) == 0 && len(b.early) >= maxLANNegotiations) {
			return false
		}
		b.early[k] = append(b.early[k], s.Data)
		return true
	case nethernet.SignalTypeError:
		// A client CONNECTERROR cancels the pending negotiation immediately,
		// freeing its slot and aborting any in-flight relay request. No reply
		// is sent for the canceled negotiation.
		e := b.pending[k]
		if e == nil {
			return false
		}
		delete(b.pending, k)
		delete(b.early, k)
		e.cancel()
		return true
	default:
		return false
	}
}

func (b *LANBridge) offer(k lanKey, e *lanExchange, offer string) {
	defer b.wg.Done()
	defer func() {
		b.mu.Lock()
		if b.pending[k] == e {
			delete(b.pending, k)
		}
		b.mu.Unlock()
	}()
	answer, err := b.exchange(k, e, offer)
	if b.ctx.Err() != nil || e.ctx.Err() != nil {
		return
	}
	typ := nethernet.SignalTypeAnswer
	if err != nil {
		code := nethernet.ErrorCodeFailedToSetRemoteDescription
		if errors.Is(err, errLANNoCandidates) {
			code = nethernet.ErrorCodeNegotiationTimeout
		}
		typ, answer = nethernet.SignalTypeError, strconv.Itoa(code)
	}
	_ = b.listener.Signal(b.ctx, &nethernet.Signal{Type: typ, NetworkID: k.network, ConnectionID: k.connection, Data: answer})
}

func (b *LANBridge) exchange(k lanKey, e *lanExchange, offer string) (string, error) {
	hard := time.NewTimer(b.gather)
	defer hard.Stop()
	quiet := time.NewTimer(b.quiet)
	defer quiet.Stop()
	// An empty initial offer waits for at least one candidate or the hard limit.
	hasCandidate := strings.Contains(offer, "a=candidate:")
	var gathered []string
	for {
		select {
		case <-e.ctx.Done():
			return "", e.ctx.Err()
		case c := <-e.candidates:
			// Accept both bare and a=-prefixed candidate attributes; skip
			// malformed lines instead of aborting the exchange.
			c = strings.TrimPrefix(c, "a=")
			if !strings.HasPrefix(c, "candidate:") || len(c) > 2048 || strings.ContainsAny(c, "\r\n") || len(gathered) >= maxCandidateLines {
				continue
			}
			gathered = append(gathered, c)
			hasCandidate = true
			if !quiet.Stop() {
				select {
				case <-quiet.C:
				default:
				}
			}
			quiet.Reset(b.quiet)
		case <-quiet.C:
			if hasCandidate {
				goto ready
			}
		case <-hard.C:
			if !hasCandidate {
				return "", errLANNoCandidates
			}
			goto ready
		}
	}
ready:
	// NetherNet uses one bundled data transport. Add trickled candidates to
	// its application media section, not at session scope or after another m=.
	if len(gathered) > 0 {
		var err error
		offer, err = lanInsertCandidates(offer, gathered)
		if err != nil {
			return "", err
		}
	}
	if len(offer) > maxBodySize {
		return "", errors.New("LAN offer too large")
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/join/"+k.network, strings.NewReader(offer)).WithContext(e.ctx)
	req.Header.Set("Content-Type", "application/sdp")
	w := httptest.NewRecorder()
	b.relay.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil || len(data) > maxBodySize || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New("HTTP relay rejected LAN offer")
	}
	if _, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 32); err == nil {
		return "", errors.New("upstream signaling error")
	}
	return string(data), nil
}

func lanInsertCandidates(offer string, candidates []string) (string, error) {
	lines := strings.SplitAfter(offer, "\n")
	start, end := -1, len(lines)
	for i, line := range lines {
		if strings.HasPrefix(line, "m=") {
			if start >= 0 {
				end = i
				break
			}
			if strings.HasPrefix(line, "m=application ") {
				start = i
			}
		}
		if start >= 0 && strings.TrimSpace(line) == "a=end-of-candidates" {
			end = i
			break
		}
	}
	if start < 0 {
		return "", errors.New("LAN offer lacks application media section")
	}
	ending := "\r\n"
	if !strings.Contains(offer, "\r\n") {
		ending = "\n"
	}
	var add strings.Builder
	if end > 0 && !strings.HasSuffix(lines[end-1], "\n") {
		add.WriteString(ending)
	}
	for _, c := range candidates {
		fmt.Fprintf(&add, "a=%s%s", c, ending)
	}
	return strings.Join(lines[:end], "") + add.String() + strings.Join(lines[end:], ""), nil
}

// Close stops discovery and waits for in-flight HTTP negotiations to cancel.
func (b *LANBridge) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.cancel()
	b.mu.Unlock()
	b.stop()
	err := b.listener.Close()
	b.wg.Wait()
	return err
}
