package netherproxy

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRelayRemapsDockerCandidatesToPeerIP verifies that when the upstream
// advertises an unroutable (Docker container) candidate, media is retargeted
// to the signaling peer's IP at the same port, and the full authenticated ICE
// path still flows through it.
func TestRelayRemapsDockerCandidatesToPeerIP(t *testing.T) {
	published, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = published.Close() })
	publishedPort := published.LocalAddr().(*net.UDPAddr).Port

	answer := "v=0\na=ice-ufrag:s\na=ice-pwd:server-secret\na=candidate:1 1 udp 1 172.17.0.9 " +
		strconv.Itoa(publishedPort) + " typ host\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, answer)
	}))
	defer upstream.Close()

	s, err := New(Config{
		RemoteURL:             upstream.URL,
		MediaBind:             "127.0.0.1:0",
		ClientAdvertiseAddr:   "127.0.0.1",
		UpstreamAdvertiseAddr: "127.0.0.1",
		Logger:                log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.closeRelays()

	offer := "v=0\na=ice-ufrag:c\na=ice-pwd:client-secret\na=candidate:1 1 udp 1 192.168.1.50 52135 typ host\n"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/v1/join/7", strings.NewReader(offer)))
	if w.Code != 200 {
		t.Fatalf("offer: %d %s", w.Code, w.Body.String())
	}

	s.mu.Lock()
	var relay *iceRelay
	for r := range s.relays {
		relay = r
	}
	s.mu.Unlock()
	if relay == nil {
		t.Fatal("no relay created")
	}
	relay.mu.Lock()
	target := relay.upstreamCandidates[0]
	relay.mu.Unlock()
	if !target.IP.Equal(net.IPv4(127, 0, 0, 1)) || target.Port != publishedPort {
		t.Fatalf("upstream target = %s, want 127.0.0.1:%d", target.String(), publishedPort)
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relay.port()}

	check := makeCheck("s:c", "server-secret", 9, false)
	if _, err := client.WriteToUDP(check, dst); err != nil {
		t.Fatal(err)
	}
	_ = published.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _, err := published.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != string(check) {
		t.Fatalf("published socket receive: n=%d err=%v match=%v", n, err, string(buf[:n]) == string(check))
	}
	if _, err := published.WriteToUDP(iceResponse(check, "server-secret"), dst); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, _, err = client.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) == string(iceResponse(check, "server-secret")) {
			break
		}
	}
}
