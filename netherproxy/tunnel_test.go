package netherproxy

import (
	"context"
	"io"
	"log"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
)

const tunnelTestDeadline = 12 * time.Second

type captureNotifier struct {
	signals chan *nethernet.Signal
}

func (c captureNotifier) NotifySignal(s *nethernet.Signal) bool {
	select {
	case c.signals <- s:
		return true
	default:
		return false
	}
}

func freeUDPPort(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()
	return addr
}

// TestLANTunnelRelaysDiscoveryAndSignaling verifies the full tunnel path: the
// upstream's advertisement is republished downstream, client signals are
// forwarded upstream with network ID translation, and upstream replies return
// to the originating client.
func TestLANTunnelRelaysDiscoveryAndSignaling(t *testing.T) {
	bdsAddr := freeUDPPort(t)
	downAddr := freeUDPPort(t)

	bdsSignals := make(chan *nethernet.Signal, 8)
	bds, err := (discovery.ListenConfig{NetworkID: 424242}).Listen(bdsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer bds.Close()
	bdsData := discovery.ServerData{
		ServerName: "Upstream World", Protocol: 2225, Version: "1.26.61",
		LevelName: "UpstreamLevel", PlayerCount: 1, MaxPlayerCount: 4,
		AcceptsOnlineAuth: true, AcceptsSelfSignedAuth: true,
		Nonce: "abcdef0123456789", ConnectionType: 4,
	}
	bds.ServerData(&bdsData)
	stopBDS := bds.Notify(captureNotifier{bdsSignals})
	defer stopBDS()

	tunnel, err := NewLANTunnel(TunnelConfig{
		BindAddr:     downAddr,
		UpstreamAddr: bdsAddr,
		Logger:       log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	clientSignals := make(chan *nethernet.Signal, 8)
	client, err := (discovery.ListenConfig{
		BroadcastAddress: mustUDP(t, downAddr),
	}).Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stopClient := client.Notify(captureNotifier{clientSignals})
	defer stopClient()

	// 1. The client discovers the tunnel and sees the upstream's advertisement.
	var got discovery.ServerData
	deadline := time.Now().Add(tunnelTestDeadline)
	for time.Now().Before(deadline) {
		if data, ok := client.Responses()[mustParseID(t, tunnel.NetworkID())]; ok {
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("decode tunneled advertisement: %v", err)
			}
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got != bdsData {
		t.Fatalf("tunneled advertisement = %+v, want %+v", got, bdsData)
	}

	// 2. The client's offer reaches the BDS with the same connection ID.
	if err := client.Signal(client.Context(), &nethernet.Signal{
		Type: nethernet.SignalTypeOffer, NetworkID: tunnel.NetworkID(),
		ConnectionID: 42, Data: "v=0 offer-data",
	}); err != nil {
		t.Fatal(err)
	}
	var bdsSeen *nethernet.Signal
	select {
	case bdsSeen = <-bdsSignals:
	case <-time.After(tunnelTestDeadline):
		t.Fatal("BDS never received the tunneled offer")
	}
	if bdsSeen.ConnectionID != 42 || bdsSeen.Data != "v=0 offer-data" || bdsSeen.Type != nethernet.SignalTypeOffer {
		t.Fatalf("BDS received %+v", bdsSeen)
	}
	// The tunnel presents the client's own identity upstream, as if the
	// client had connected without a proxy.
	if bdsSeen.NetworkID != client.NetworkID() {
		t.Fatalf("offer arrived from %s, want the client's own identity %s", bdsSeen.NetworkID, client.NetworkID())
	}

	// 3. The BDS answer returns to the client.
	if err := bds.Signal(bds.Context(), &nethernet.Signal{
		Type: nethernet.SignalTypeAnswer, NetworkID: bdsSeen.NetworkID,
		ConnectionID: 42, Data: "v=0 answer-data",
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-clientSignals:
		if s.ConnectionID != 42 || s.Data != "v=0 answer-data" || s.Type != nethernet.SignalTypeAnswer {
			t.Fatalf("client received %+v", s)
		}
	case <-time.After(tunnelTestDeadline):
		t.Fatal("client never received the tunneled answer")
	}
}

func mustUDP(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	resolved, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func mustParseID(t *testing.T, id string) uint64 {
	t.Helper()
	parsed, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// TestLANTunnelMediaAssistRewritesDockerCandidates verifies that with
// MediaAssist, an upstream answer advertising an unroutable (Docker container)
// candidate is rewritten to a proxy socket whose media reaches the upstream
// host at the advertised port, bidirectionally.
func TestLANTunnelMediaAssistRewritesDockerCandidates(t *testing.T) {
	bdsAddr := freeUDPPort(t)
	downAddr := freeUDPPort(t)

	published, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = published.Close() })
	publishedPort := published.LocalAddr().(*net.UDPAddr).Port

	bdsSignals := make(chan *nethernet.Signal, 8)
	bds, err := (discovery.ListenConfig{NetworkID: 424243}).Listen(bdsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer bds.Close()
	bds.ServerData(&discovery.ServerData{
		ServerName: "Docker Upstream", Protocol: 2225, Version: "1.26.61",
		AcceptsSelfSignedAuth: true, ConnectionType: 4,
	})
	stopBDS := bds.Notify(captureNotifier{bdsSignals})
	defer stopBDS()

	tunnel, err := NewLANTunnel(TunnelConfig{
		BindAddr:     downAddr,
		UpstreamAddr: bdsAddr,
		MediaAssist:  true,
		AdvertiseIP:  net.IPv4(127, 0, 0, 1),
		MediaBind:    "127.0.0.1:0",
		Logger:       log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	clientSignals := make(chan *nethernet.Signal, 8)
	client, err := (discovery.ListenConfig{
		BroadcastAddress: mustUDP(t, downAddr),
	}).Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	stopClient := client.Notify(captureNotifier{clientSignals})
	defer stopClient()

	// Wait for the client to receive the tunnel's republished advertisement
	// (this also teaches the client the tunnel's signaling address).
	deadline := time.Now().Add(tunnelTestDeadline)
	for time.Now().Before(deadline) {
		if _, ok := client.Responses()[mustParseID(t, tunnel.NetworkID())]; ok {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, ok := client.Responses()[mustParseID(t, tunnel.NetworkID())]; !ok {
		t.Fatal("client never received the tunnel advertisement")
	}

	// Client offer passes through to the BDS.
	if err := client.Signal(client.Context(), &nethernet.Signal{
		Type: nethernet.SignalTypeOffer, NetworkID: tunnel.NetworkID(),
		ConnectionID: 7, Data: "v=0\na=ice-ufrag:c\na=candidate:1 1 udp 1 192.168.1.50 52135 typ host\n",
	}); err != nil {
		t.Fatal(err)
	}
	var bdsSeen *nethernet.Signal
	select {
	case bdsSeen = <-bdsSignals:
	case <-time.After(tunnelTestDeadline):
		t.Fatal("BDS never received the offer")
	}

	// The BDS answers with an unroutable Docker-style candidate.
	answer := "v=0\na=ice-ufrag:s\na=candidate:1 1 udp 1 172.17.0.9 " + strconv.Itoa(publishedPort) + " typ host\n"
	if err := bds.Signal(bds.Context(), &nethernet.Signal{
		Type: nethernet.SignalTypeAnswer, NetworkID: bdsSeen.NetworkID,
		ConnectionID: 7, Data: answer,
	}); err != nil {
		t.Fatal(err)
	}
	var rewritten string
	select {
	case s := <-clientSignals:
		if s.ConnectionID != 7 || s.Type != nethernet.SignalTypeAnswer {
			t.Fatalf("client received %+v", s)
		}
		rewritten = s.Data
	case <-time.After(tunnelTestDeadline):
		t.Fatal("client never received the answer")
	}
	if strings.Contains(rewritten, "172.17.0.9") || !strings.Contains(rewritten, "127.0.0.1") {
		t.Fatalf("answer not rewritten: %q", rewritten)
	}

	// Extract the assist port from the rewritten candidate and drive media
	// through it in both directions via the published port.
	fields := strings.Fields(rewritten)
	assistPort := 0
	for i, f := range fields {
		if f == "127.0.0.1" && i+1 < len(fields) {
			assistPort, err = strconv.Atoi(fields[i+1])
			if err == nil {
				break
			}
		}
	}
	if assistPort == 0 {
		t.Fatalf("no rewritten candidate found in %q", rewritten)
	}

	mediaClient, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mediaClient.Close() })
	assistAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: assistPort}
	if _, err := mediaClient.WriteToUDP([]byte("media-up"), assistAddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	_ = published.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := published.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "media-up" {
		t.Fatalf("published socket: n=%d err=%v body=%q", n, err, string(buf[:n]))
	}
	if _, err := published.WriteToUDP([]byte("media-down"), assistAddr); err != nil {
		t.Fatal(err)
	}
	_ = mediaClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = mediaClient.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "media-down" {
		t.Fatalf("media client: n=%d err=%v body=%q", n, err, string(buf[:n]))
	}
}

// TestAssistMediaKeepsRouteAlive verifies that media traffic refreshing a
// route prevents the idle sweeper from closing a live assist relay, while a
// genuinely idle route is still reaped. Regression test for sessions dying
// routeTTL after join despite active gameplay.
func TestAssistMediaKeepsRouteAlive(t *testing.T) {
	bdsAddr := freeUDPPort(t)
	downAddr := freeUDPPort(t)

	published, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = published.Close() })
	publishedPort := published.LocalAddr().(*net.UDPAddr).Port

	bds, err := (discovery.ListenConfig{NetworkID: 424244}).Listen(bdsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer bds.Close()
	bds.ServerData(&discovery.ServerData{
		ServerName: "Idle Reaper", Protocol: 2225, Version: "1.26.61",
		AcceptsSelfSignedAuth: true, ConnectionType: 4,
	})
	bdsSignals := make(chan *nethernet.Signal, 8)
	stopBDS := bds.Notify(captureNotifier{bdsSignals})
	defer stopBDS()

	const routeTTL = 600 * time.Millisecond
	tunnel, err := NewLANTunnel(TunnelConfig{
		BindAddr:     downAddr,
		UpstreamAddr: bdsAddr,
		RouteTTL:     routeTTL,
		MediaAssist:  true,
		AdvertiseIP:  net.IPv4(127, 0, 0, 1),
		MediaBind:    "127.0.0.1:0",
		MediaIdleTTL: 10 * time.Second,
		Logger:       log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	client, err := (discovery.ListenConfig{
		BroadcastAddress: mustUDP(t, downAddr),
	}).Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	clientSignals := make(chan *nethernet.Signal, 8)
	stopClient := client.Notify(captureNotifier{clientSignals})
	defer stopClient()

	// Complete discovery + offer/answer to establish a routed assist relay.
	deadline := time.Now().Add(tunnelTestDeadline)
	for time.Now().Before(deadline) {
		if _, ok := client.Responses()[mustParseID(t, tunnel.NetworkID())]; ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := client.Signal(client.Context(), &nethernet.Signal{
		Type: nethernet.SignalTypeOffer, NetworkID: tunnel.NetworkID(),
		ConnectionID: 9, Data: "v=0\na=ice-ufrag:c\na=candidate:1 1 udp 1 192.168.1.50 52135 typ host\n",
	}); err != nil {
		t.Fatal(err)
	}
	var bdsSeen *nethernet.Signal
	select {
	case bdsSeen = <-bdsSignals:
	case <-time.After(tunnelTestDeadline):
		t.Fatal("BDS never received the offer")
	}
	answer := "v=0\na=ice-ufrag:s\na=candidate:1 1 udp 1 172.17.0.9 " + strconv.Itoa(publishedPort) + " typ host\n"
	if err := bds.Signal(bds.Context(), &nethernet.Signal{
		Type: nethernet.SignalTypeAnswer, NetworkID: bdsSeen.NetworkID,
		ConnectionID: 9, Data: answer,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-clientSignals:
		if s.ConnectionID != 9 {
			t.Fatalf("client received %+v", s)
		}
	case <-time.After(tunnelTestDeadline):
		t.Fatal("client never received the rewritten answer")
	}

	tunnel.mu.Lock()
	r, ok := tunnel.routes[9]
	tunnel.mu.Unlock()
	if !ok || r.assist == nil {
		t.Fatal("route with assist not established")
	}
	assist := r.assist

	// Find the assist port from the tunnel's log-free state: bind a media
	// client and locate the assist socket port via the relay's conn.
	mediaClient, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mediaClient.Close() })
	assistPort := assist.conn.LocalAddr().(*net.UDPAddr).Port
	assistAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: assistPort}

	// Drive media well past routeTTL; each packet refreshes the route.
	buf := make([]byte, 128)
	for i := 0; i < 8; i++ {
		if _, err := mediaClient.WriteToUDP([]byte("keepalive"), assistAddr); err != nil {
			t.Fatal(err)
		}
		_ = published.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := published.ReadFromUDP(buf)
		if err != nil || string(buf[:n]) != "keepalive" {
			t.Fatalf("media stopped mid-session: n=%d err=%v", n, err)
		}
		time.Sleep(routeTTL / 2)
	}
	// A sweep now must NOT close the live session.
	tunnel.sweepRoutes()
	select {
	case <-assist.closed:
		t.Fatal("sweep closed a media-active assist relay")
	default:
	}
	if _, err := mediaClient.WriteToUDP([]byte("still-alive"), assistAddr); err != nil {
		t.Fatal(err)
	}
	_ = published.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := published.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "still-alive" {
		t.Fatalf("media dead after sweep: n=%d err=%v", n, err)
	}

	// Go idle beyond routeTTL; the sweep must now reap route and relay.
	time.Sleep(routeTTL * 2)
	tunnel.sweepRoutes()
	select {
	case <-assist.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("idle assist relay was not reaped")
	}
	tunnel.mu.Lock()
	_, stillRouted := tunnel.routes[9]
	tunnel.mu.Unlock()
	if stillRouted {
		t.Fatal("idle route was not reaped")
	}
}

// TestLANTunnelGivesEachClientItsOwnIdentity establishes two concurrent
// clients through one tunnel against a BDS that accepts real WebRTC
// connections, and verifies the BDS sees a distinct upstream identity per
// client, equal to each client's own network ID. A single shared identity made
// concurrent clients collide at the Bedrock session layer.
func TestLANTunnelGivesEachClientItsOwnIdentity(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	bdsAddr := freeUDPPort(t)
	downAddr := freeUDPPort(t)

	// The BDS: LAN discovery plus a real accepting WebRTC listener.
	bdsSignals := make(chan *nethernet.Signal, 64)
	bdsDisc, err := (discovery.ListenConfig{NetworkID: 424245}).Listen(bdsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer bdsDisc.Close()
	bdsDisc.ServerData(&discovery.ServerData{
		ServerName: "Two Peers", Protocol: 2225, Version: "1.26.61",
		AcceptsSelfSignedAuth: true, ConnectionType: 4,
	})
	stopSniff := bdsDisc.Notify(captureNotifier{bdsSignals})
	defer stopSniff()
	// Real BDS accepts identity-less LAN offers; mirror that here.
	bds, err := (nethernet.ListenConfig{Log: quiet, AllowAnonymous: true}).Listen(bdsDisc)
	if err != nil {
		t.Fatal(err)
	}
	defer bds.Close()

	tunnel, err := NewLANTunnel(TunnelConfig{
		BindAddr:     downAddr,
		UpstreamAddr: bdsAddr,
		Logger:       log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	tunnelID := mustParseID(t, tunnel.NetworkID())

	// Two clients discover the tunnel through its republished advertisement.
	type clientPeer struct {
		l *discovery.Listener
	}
	var peers []clientPeer
	for i := 0; i < 2; i++ {
		l, err := (discovery.ListenConfig{BroadcastAddress: mustUDP(t, downAddr)}).Listen("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		l.Notify(captureNotifier{make(chan *nethernet.Signal, 64)})
		peers = append(peers, clientPeer{l: l})
	}
	deadline := time.Now().Add(tunnelTestDeadline)
	for _, p := range peers {
		for {
			if _, ok := p.l.Responses()[tunnelID]; ok {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("client never discovered the tunnel")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Both dial at the same time, as two consoles joining together would.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	type result struct {
		err  error
		conn *nethernet.Conn
	}
	results := make(chan result, len(peers))
	for _, p := range peers {
		go func(l *discovery.Listener) {
			d := nethernet.Dialer{Log: quiet, AllowIdentitylessServer: true, ConnectionID: rand.Uint64()}
			conn, err := d.DialContext(ctx, tunnel.NetworkID(), l)
			results <- result{err, conn}
		}(p.l)
	}
	var conns []*nethernet.Conn
	for range peers {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("concurrent client failed through the tunnel: %v", r.err)
			}
			conns = append(conns, r.conn)
		case <-time.After(30 * time.Second):
			t.Fatal("concurrent client never connected")
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}

	// The BDS must have seen one offer from each client's own identity.
	seen := map[string]bool{}
	for len(seen) < len(peers) {
		select {
		case s := <-bdsSignals:
			if s.Type == nethernet.SignalTypeOffer {
				seen[s.NetworkID] = true
			}
		case <-time.After(tunnelTestDeadline):
			t.Fatalf("BDS saw %d distinct offering identities, want %d: %v", len(seen), len(peers), seen)
		}
	}
	for i, p := range peers {
		if !seen[p.l.NetworkID()] {
			t.Fatalf("BDS never saw client %d's own identity %s (saw %v)", i, p.l.NetworkID(), seen)
		}
	}
}
