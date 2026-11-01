package netherproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
)

func TestLANDiscoveryAndSignaling(t *testing.T) {
	reserve, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := reserve.LocalAddr().String()
	reserve.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/v1/join/77" || !strings.Contains(string(body), "10.0.0.2") || !strings.Contains(string(body), "a=identity:client") {
			t.Errorf("unexpected offer: %s %s", r.URL.Path, body)
		}
		fmt.Fprint(w, "v=0\r\na=identity:server\r\na=ice-ufrag:server\r\na=ice-pwd:serverpassword\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=candidate:1 1 udp 1 127.0.0.1 4567 typ host\r\n")
	}))
	defer upstream.Close()
	relay, err := New(Config{RemoteURL: upstream.URL, MediaBind: "127.0.0.1:0", ClientAdvertiseAddr: "10.0.0.1", UpstreamAdvertiseAddr: "10.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.closeRelays()
	b, err := NewLANBridge(LANConfig{BindAddr: addr, NetworkID: 99, QuietWindow: 30 * time.Millisecond, GatherTimeout: time.Second, Data: discovery.ServerData{ServerName: "test", Protocol: 900, Version: "test", AcceptsOnlineAuth: true, ConnectionType: 4}}, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	c, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	write := func(p discovery.Packet) {
		t.Helper()
		if _, err := c.Write(discovery.Marshal(p, 77)); err != nil {
			t.Fatal(err)
		}
	}
	read := func() discovery.Packet {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 65535)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		p, id, err := discovery.Unmarshal(buf[:n])
		if err != nil || id != 99 {
			t.Fatalf("decode %d %v", id, err)
		}
		return p
	}
	write(&discovery.RequestPacket{})
	response, ok := read().(*discovery.ResponsePacket)
	if !ok {
		t.Fatal("expected discovery response")
	}
	var data discovery.ServerData
	if err := data.UnmarshalBinary(response.ApplicationData); err != nil || data.ServerName != "test" || data.Protocol != 900 {
		t.Fatalf("discovery: %+v %v", data, err)
	}
	offer := "v=0\r\na=identity:client\r\na=ice-ufrag:client\r\na=ice-pwd:clientpassword\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
	write(&discovery.MessagePacket{RecipientID: 99, Data: (&nethernet.Signal{Type: nethernet.SignalTypeOffer, ConnectionID: 5, Data: offer}).String()})
	write(&discovery.MessagePacket{RecipientID: 99, Data: (&nethernet.Signal{Type: nethernet.SignalTypeCandidate, ConnectionID: 5, Data: "candidate:1 1 udp 1 127.0.0.1 1234 typ host"}).String()})
	msg, ok := read().(*discovery.MessagePacket)
	if !ok || msg.RecipientID != 77 {
		t.Fatal("expected signaling response")
	}
	var signal nethernet.Signal
	if err := signal.UnmarshalText([]byte(msg.Data)); err != nil || signal.Type != nethernet.SignalTypeAnswer || signal.ConnectionID != 5 || !strings.Contains(signal.Data, "a=identity:server") || !strings.Contains(signal.Data, "10.0.0.1") {
		t.Fatalf("answer: %+v %v", signal, err)
	}
}

func TestLANBoundsAndCancellation(t *testing.T) {
	b, err := NewLANBridge(LANConfig{BindAddr: "127.0.0.1:0", NetworkID: 9, QuietWindow: time.Second, GatherTimeout: 2 * time.Second, Data: discovery.ServerData{Protocol: 1, Version: "1", AcceptsOnlineAuth: true, ConnectionType: 4}}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected HTTP call") }))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 64; i++ {
		if !b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeOffer, NetworkID: "7", ConnectionID: uint64(i), Data: "v=0\n"}) {
			t.Fatal("offer rejected")
		}
	}
	if b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeOffer, NetworkID: "7", ConnectionID: 64}) {
		t.Fatal("capacity exceeded")
	}
	if b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeOffer, NetworkID: "7", ConnectionID: 1}) {
		t.Fatal("duplicate accepted")
	}
	if b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeError, NetworkID: "7", ConnectionID: 12345, Data: strconv.Itoa(nethernet.ErrorCodeGenericFailure)}) {
		t.Fatal("error accepted for unknown negotiation")
	}
	if !b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeError, NetworkID: "7", ConnectionID: 0, Data: strconv.Itoa(nethernet.ErrorCodeGenericFailure)}) {
		t.Fatal("cancellation rejected")
	}
	if !b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeOffer, NetworkID: "7", ConnectionID: 0, Data: "v=0\n"}) {
		t.Fatal("slot not freed after cancellation")
	}
	done := make(chan struct{})
	go func() { b.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close blocked")
	}
	if b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeOffer, NetworkID: "7"}) {
		t.Fatal("accepted after close")
	}
}

func TestLANInsertCandidates(t *testing.T) {
	s := "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:0\r\nm=other 9 UDP foo\r\n"
	got, err := lanInsertCandidates(s, []string{"candidate:1 1 udp 1 127.0.0.1 9 typ host"})
	if err != nil || !strings.Contains(got, "a=mid:0\r\na=candidate:1 1 udp 1 127.0.0.1 9 typ host\r\nm=other") {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := lanInsertCandidates("v=0\n", nil); err == nil {
		t.Fatal("missing media accepted")
	}
}

const (
	lanTestOffer  = "v=0\r\na=identity:client\r\na=ice-ufrag:client\r\na=ice-pwd:clientpassword\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
	lanTestAnswer = "v=0\r\na=identity:server\r\na=ice-ufrag:server\r\na=ice-pwd:serverpassword\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
)

func lanTestBridge(t *testing.T, quiet, gather time.Duration, relay http.Handler) *LANBridge {
	t.Helper()
	b, err := NewLANBridge(LANConfig{BindAddr: "127.0.0.1:0", NetworkID: 9, QuietWindow: quiet, GatherTimeout: gather, Data: discovery.ServerData{Protocol: 1, Version: "1", AcceptsOnlineAuth: true, ConnectionType: 4}}, relay)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// lanCaptureRelay records each relayed offer and returns a valid answer.
func lanCaptureRelay(offers chan<- string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		offers <- string(body)
		fmt.Fprint(w, lanTestAnswer)
	})
}

// lanSignalHarness drives one LANBridge over loopback UDP signaling. Signals
// are sent from network 77 and read back as the bridge's replies.
func lanSignalHarness(t *testing.T, cfg LANConfig, relay http.Handler) (write func(*nethernet.Signal), read func(time.Duration) (*nethernet.Signal, error)) {
	t.Helper()
	reserve, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := reserve.LocalAddr().String()
	reserve.Close()
	cfg.BindAddr = addr
	b, err := NewLANBridge(cfg, relay)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	c, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	write = func(s *nethernet.Signal) {
		t.Helper()
		if _, err := c.Write(discovery.Marshal(&discovery.MessagePacket{RecipientID: cfg.NetworkID, Data: s.String()}, 77)); err != nil {
			t.Fatal(err)
		}
	}
	read = func(timeout time.Duration) (*nethernet.Signal, error) {
		if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		p, id, err := discovery.Unmarshal(buf[:n])
		if err != nil {
			return nil, err
		}
		msg, ok := p.(*discovery.MessagePacket)
		if !ok {
			return nil, fmt.Errorf("unexpected packet %T", p)
		}
		if id != cfg.NetworkID || msg.RecipientID != 77 {
			return nil, fmt.Errorf("unexpected packet id=%d recipient=%d", id, msg.RecipientID)
		}
		var s nethernet.Signal
		if err := s.UnmarshalText([]byte(msg.Data)); err != nil {
			return nil, err
		}
		return &s, nil
	}
	return write, read
}

func TestLANCandidateBeforeOffer(t *testing.T) {
	offers := make(chan string, 4)
	b := lanTestBridge(t, 20*time.Millisecond, time.Second, lanCaptureRelay(offers))
	const cid = 3
	// 33 candidates before the offer: the first 32 are buffered, the rest dropped.
	for i := 0; i < 33; i++ {
		accepted := b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeCandidate, NetworkID: "7", ConnectionID: cid, Data: fmt.Sprintf("candidate:1 1 udp 1 127.0.0.1 %d typ host", 5000+i)})
		if i < 32 && !accepted {
			t.Fatalf("early candidate %d dropped", i)
		}
		if i >= 32 && accepted {
			t.Fatal("early candidate buffer unbounded")
		}
	}
	if !b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeOffer, NetworkID: "7", ConnectionID: cid, Data: lanTestOffer}) {
		t.Fatal("offer rejected")
	}
	select {
	case offer := <-offers:
		if !strings.Contains(offer, "candidate:1 1 udp 1 127.0.0.1 5000 typ host") {
			t.Fatalf("first early candidate missing: %s", offer)
		}
		if !strings.Contains(offer, "candidate:1 1 udp 1 127.0.0.1 5031 typ host") {
			t.Fatalf("last buffered candidate missing: %s", offer)
		}
		if strings.Contains(offer, "5032") {
			t.Fatalf("candidate beyond buffer forwarded: %s", offer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no offer relayed")
	}
}

func TestLANCandidateAttributePrefix(t *testing.T) {
	offers := make(chan string, 4)
	b := lanTestBridge(t, 20*time.Millisecond, time.Second, lanCaptureRelay(offers))
	if !b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeOffer, NetworkID: "7", ConnectionID: 4, Data: lanTestOffer}) {
		t.Fatal("offer rejected")
	}
	if !b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeCandidate, NetworkID: "7", ConnectionID: 4, Data: "a=candidate:1 1 udp 1 127.0.0.1 6001 typ host"}) {
		t.Fatal("a=-prefixed candidate rejected")
	}
	select {
	case offer := <-offers:
		if !strings.Contains(offer, "a=candidate:1 1 udp 1 127.0.0.1 6001 typ host\r\n") {
			t.Fatalf("a=-prefixed candidate not inserted: %s", offer)
		}
		if strings.Contains(offer, "a=a=") {
			t.Fatalf("doubled attribute prefix: %s", offer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no offer relayed")
	}
}

func TestLANMalformedCandidateSkipped(t *testing.T) {
	offers := make(chan string, 4)
	b := lanTestBridge(t, 20*time.Millisecond, time.Second, lanCaptureRelay(offers))
	if !b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeOffer, NetworkID: "7", ConnectionID: 5, Data: lanTestOffer}) {
		t.Fatal("offer rejected")
	}
	b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeCandidate, NetworkID: "7", ConnectionID: 5, Data: "garbage"})
	b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeCandidate, NetworkID: "7", ConnectionID: 5, Data: "candidate:1 1 udp 1 127.0.0.1 6002 typ host\r\njunk"})
	if !b.NotifySignal(&nethernet.Signal{Type: nethernet.SignalTypeCandidate, NetworkID: "7", ConnectionID: 5, Data: "candidate:1 1 udp 1 127.0.0.1 6003 typ host"}) {
		t.Fatal("valid candidate rejected")
	}
	select {
	case offer := <-offers:
		if !strings.Contains(offer, "candidate:1 1 udp 1 127.0.0.1 6003 typ host") {
			t.Fatalf("valid candidate missing: %s", offer)
		}
		if strings.Contains(offer, "garbage") || strings.Contains(offer, "6002") || strings.Contains(offer, "junk") {
			t.Fatalf("malformed candidate not skipped: %s", offer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no offer relayed")
	}
}

func TestLANConnectErrorCancelsNegotiation(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	relay := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
			<-r.Context().Done()
			return
		}
		fmt.Fprint(w, lanTestAnswer)
	})
	write, read := lanSignalHarness(t, LANConfig{BindAddr: "127.0.0.1:0", NetworkID: 10, QuietWindow: 50 * time.Millisecond, GatherTimeout: 2 * time.Second, Data: discovery.ServerData{Protocol: 1, Version: "1", AcceptsOnlineAuth: true, ConnectionType: 4}}, relay)
	offer := lanTestOffer + "a=candidate:1 1 udp 1 127.0.0.1 7000 typ host\r\n"
	write(&nethernet.Signal{Type: nethernet.SignalTypeOffer, ConnectionID: 5, Data: offer})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("relay never saw the offer")
	}
	write(&nethernet.Signal{Type: nethernet.SignalTypeError, ConnectionID: 5, Data: strconv.Itoa(nethernet.ErrorCodeGenericFailure)})
	if s, err := read(300 * time.Millisecond); err == nil {
		t.Fatalf("unexpected reply to canceled negotiation: %+v", s)
	}
	// The slot was freed, so a retry offer for the same connection is accepted and answered.
	write(&nethernet.Signal{Type: nethernet.SignalTypeOffer, ConnectionID: 5, Data: offer})
	s, err := read(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if s.Type != nethernet.SignalTypeAnswer || s.ConnectionID != 5 {
		t.Fatalf("retry not answered: %+v", s)
	}
}

func TestLANNoCandidateHardTimeout(t *testing.T) {
	relay := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected HTTP call") })
	write, read := lanSignalHarness(t, LANConfig{BindAddr: "127.0.0.1:0", NetworkID: 11, QuietWindow: 20 * time.Millisecond, GatherTimeout: 60 * time.Millisecond, Data: discovery.ServerData{Protocol: 1, Version: "1", AcceptsOnlineAuth: true, ConnectionType: 4}}, relay)
	write(&nethernet.Signal{Type: nethernet.SignalTypeOffer, ConnectionID: 6, Data: lanTestOffer})
	s, err := read(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if s.Type != nethernet.SignalTypeError || s.ConnectionID != 6 || s.Data != strconv.Itoa(nethernet.ErrorCodeNegotiationTimeout) {
		t.Fatalf("want negotiation-timeout error: %+v", s)
	}
}
