package netherproxy

import (
	"io"
	"log"
	"net"
	"strconv"
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
	if bdsSeen.NetworkID != tunnel.up.NetworkID() {
		t.Fatalf("offer arrived from %s, want tunnel upstream ID %s", bdsSeen.NetworkID, tunnel.up.NetworkID())
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
