package netherproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRelayForwardsNetherNetEndpoints(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/join" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"protocol":2225}`)
			return
		}
		if r.URL.Path == "/v1/join/123" && r.Method == http.MethodPost {
			if got := r.Header.Get("Content-Type"); got != "application/sdp" {
				http.Error(w, fmt.Sprintf("content type %q", got), http.StatusBadRequest)
				return
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "10.0.0.2") {
				http.Error(w, "offer candidate was not rewritten", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/sdp")
			_, _ = w.Write([]byte("v=0\na=candidate:1 1 udp 1 10.0.0.2 4567 typ host\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	relay, err := New(Config{
		BindAddr:              "127.0.0.1:0",
		RemoteURL:             upstream.URL,
		MediaBind:             "127.0.0.1:0",
		ClientAdvertiseAddr:   "10.0.0.1",
		UpstreamAdvertiseAddr: "10.0.0.2",
		Logger:                log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := httptest.NewServer(relay)
	defer client.Close()

	resp, err := http.Get(client.URL + "/v1/join")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != `{"protocol":2225}` {
		t.Fatalf("GET relay: status=%d body=%q", resp.StatusCode, body)
	}

	offer := "v=0\na=candidate:1 1 udp 1 10.0.0.3 1234 typ host\n"
	resp, err = http.Post(client.URL+"/v1/join/123", "application/sdp", strings.NewReader(offer))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "10.0.0.1") {
		t.Fatalf("POST relay: status=%d body=%q", resp.StatusCode, body)
	}
}

func TestRelayRejectsNonSignalingPaths(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	relay, err := New(Config{
		RemoteURL:             upstream.URL,
		ClientAdvertiseAddr:   "10.0.0.1",
		UpstreamAdvertiseAddr: "10.0.0.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	resp := httptest.NewRecorder()
	relay.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", resp.Code)
	}
}

func TestRelayServeStopsWithContext(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	relay, err := New(Config{
		BindAddr:              "127.0.0.1:0",
		RemoteURL:             upstream.URL,
		MediaBind:             "127.0.0.1:0",
		ClientAdvertiseAddr:   "10.0.0.1",
		UpstreamAdvertiseAddr: "10.0.0.2",
		Logger:                log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- relay.Serve(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestICERelayForwardsBothDirections(t *testing.T) {
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	relay, err := newIceRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.close()
	relay.setUpstream([]net.UDPAddr{*upstream.LocalAddr().(*net.UDPAddr)})

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.WriteToUDP([]byte("to-upstream"), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: relay.port()}); err != nil {
		t.Fatal(err)
	}
	_ = upstream.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, clientAddr, err := upstream.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "to-upstream" {
		t.Fatalf("upstream receive: n=%d err=%v body=%q", n, err, buf[:n])
	}
	if _, err := upstream.WriteToUDP([]byte("to-client"), clientAddr); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = client.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "to-client" {
		t.Fatalf("client receive: n=%d err=%v body=%q", n, err, buf[:n])
	}
}
