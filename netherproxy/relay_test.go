package netherproxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
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
			_, _ = w.Write([]byte("v=0\na=ice-ufrag:server\na=ice-pwd:serverpassword\na=candidate:1 1 udp 1 10.0.0.2 4567 typ host\n"))
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
	defer relay.closeRelays()
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

	offer := "v=0\na=ice-ufrag:client\na=ice-pwd:clientpassword\na=candidate:1 1 udp 1 10.0.0.3 1234 typ host\n"
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

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	relay.configure([]net.UDPAddr{*client.LocalAddr().(*net.UDPAddr)}, []net.UDPAddr{*upstream.LocalAddr().(*net.UDPAddr)}, "client", "clientpassword", "server", "serverpassword")
	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: relay.port()}
	check := iceCheck("server:client", "serverpassword")
	if _, err := client.WriteToUDP(check, target); err != nil {
		t.Fatal(err)
	}
	_ = upstream.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	n, clientAddr, err := upstream.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != string(check) {
		t.Fatalf("upstream receive: n=%d err=%v body=%q", n, err, buf[:n])
	}
	if _, err := upstream.WriteToUDP(iceCheck("client:server", "clientpassword"), clientAddr); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err = client.ReadFromUDP(buf); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(iceResponse(iceCheck("client:server", "clientpassword"), "clientpassword"), target); err != nil {
		t.Fatal(err)
	}
	if _, _, err := upstream.ReadFromUDP(buf); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP([]byte("to-upstream"), target); err != nil {
		t.Fatal(err)
	}
	if n, _, err = upstream.ReadFromUDP(buf); err != nil || string(buf[:n]) != "to-upstream" {
		t.Fatalf("client data: %q %v", buf[:n], err)
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

func iceCheck(username, password string) []byte {
	return makeCheck(username, password, 0, false)
}

func makeCheck(username, password string, id byte, nominate bool) []byte {
	p := make([]byte, 20)
	binary.BigEndian.PutUint16(p, 1)
	binary.BigEndian.PutUint32(p[4:], 0x2112a442)
	p[19] = id
	p = binary.BigEndian.AppendUint16(p, 6)
	p = binary.BigEndian.AppendUint16(p, uint16(len(username)))
	p = append(p, username...)
	for len(p)%4 != 0 {
		p = append(p, 0)
	}
	if nominate {
		p = append(p, 0, 0x25, 0, 0, 0x80, 0x2a, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1)
	}
	return signSTUN(p, password)
}

func iceResponse(request []byte, password string) []byte {
	p := append([]byte(nil), request[:20]...)
	binary.BigEndian.PutUint16(p, 0x0101)
	p = append(p, 0, 0x20, 0, 8, 0, 1, 0, 0, 0, 0, 0, 0)
	return signSTUN(p, password)
}

func signSTUN(p []byte, password string) []byte {
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)+24-20))
	mac := hmac.New(sha1.New, []byte(password))
	_, _ = mac.Write(p)
	p = binary.BigEndian.AppendUint16(p, 8)
	p = binary.BigEndian.AppendUint16(p, 20)
	return append(p, mac.Sum(nil)...)
}

func TestICECheckRejectsForgedAndMalformed(t *testing.T) {
	good := iceCheck("server:client", "secret")
	if !validICECheck(good, "server:client", "secret") {
		t.Fatal("valid check rejected")
	}
	if validICECheck(good, "client:server", "secret") || validICECheck(good, "server:client", "wrong") {
		t.Fatal("wrong credentials accepted")
	}
	for i := range good {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0x80
		if validICECheck(bad, "server:client", "secret") {
			t.Fatalf("mutation at %d accepted", i)
		}
	}
	for i := range good {
		if validICECheck(good[:i], "server:client", "secret") {
			t.Fatalf("truncated packet %d accepted", i)
		}
	}
}

func TestRFC5769Request(t *testing.T) {
	packet, err := hex.DecodeString("000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf")
	if err != nil {
		t.Fatal(err)
	}
	if !validICECheck(packet, "evtj:h6vY", "VOkJxbRl1RmTxUk/WvJxBt") {
		t.Fatal("RFC 5769 test vector rejected")
	}
	response, err := hex.DecodeString("0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a147e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96")
	if err != nil {
		t.Fatal(err)
	}
	if !validSTUNIntegrity(response, 0x0101, "", "VOkJxbRl1RmTxUk/WvJxBt", false) || !hasMappedAddress(response) {
		t.Fatal("RFC 5769 response vector rejected")
	}
}

func TestIndependentOffersAndCapacity(t *testing.T) {
	answer := "v=0\na=ice-ufrag:s\na=ice-pwd:serverpassword\na=candidate:1 1 udp 1 127.0.0.1 1234 typ host\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, answer) }))
	defer upstream.Close()
	s, err := New(Config{RemoteURL: upstream.URL, MediaBind: "127.0.0.1:0", ClientAdvertiseAddr: "127.0.0.1", UpstreamAdvertiseAddr: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.closeRelays()
	offer := "v=0\na=ice-ufrag:c\na=ice-pwd:clientpassword\na=candidate:1 1 udp 1 127.0.0.1 1235 typ host\n"
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("POST", "/v1/join/42", strings.NewReader(offer)))
		if w.Code != 200 {
			t.Fatalf("offer %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	s.mu.Lock()
	if len(s.relays) != 2 {
		t.Fatalf("got %d relays", len(s.relays))
	}
	for len(s.relays) < maxRelays {
		s.relays[&iceRelay{}] = struct{}{}
	}
	s.mu.Unlock()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/v1/join/42", strings.NewReader(offer)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity status %d", w.Code)
	}
	s.mu.Lock()
	for r := range s.relays {
		if r.conn == nil {
			delete(s.relays, r)
		}
	}
	s.mu.Unlock()
}

func TestRelayRejectsHijackAndLearnsPeerReflexive(t *testing.T) {
	open := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	client, upstream, attacker := open(), open(), open()
	r, err := newIceRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	// Neither real endpoint is among the advertised addresses.
	r.configure([]net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 9}}, []net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 9}}, "c", "client-secret", "s", "server-secret")
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.port()}
	_, _ = attacker.WriteToUDP([]byte("fake"), dst)
	_, _ = attacker.WriteToUDP(iceCheck("s:c", "wrong"), dst)
	_, _ = client.WriteToUDP(iceCheck("s:c", "server-secret"), dst)
	_, _ = upstream.WriteToUDP(iceCheck("c:s", "client-secret"), dst)
	// A retransmitted client check reaches the learned peer-reflexive source.
	time.Sleep(20 * time.Millisecond)
	check := makeCheck("s:c", "server-secret", 4, true)
	_, _ = client.WriteToUDP(check, dst)
	_ = upstream.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	for {
		n, _, err := upstream.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) == string(check) {
			break
		}
	}
	_, _ = upstream.WriteToUDP(iceResponse(check, "server-secret"), dst)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	for {
		n, _, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) == string(iceResponse(check, "server-secret")) {
			break
		}
	}
	// An uncorrelated response cannot replace the selected endpoint.
	_, _ = attacker.WriteToUDP(iceResponse(check, "server-secret"), dst)
	_, _ = client.WriteToUDP([]byte("real-data"), dst)
	_ = upstream.SetReadDeadline(time.Now().Add(time.Second))
	for {
		n, _, err := upstream.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) == "real-data" {
			break
		}
	}
	r.mu.Lock()
	gotClient, gotUpstream := r.client.String(), r.upstream.String()
	r.mu.Unlock()
	if gotClient != client.LocalAddr().String() || gotUpstream != upstream.LocalAddr().String() {
		t.Fatalf("endpoints changed: %s %s", gotClient, gotUpstream)
	}
}

func TestCredentialsAndCandidateBounds(t *testing.T) {
	for _, sdp := range []string{"", "a=ice-ufrag:x\na=ice-pwd:y\na=ice-ufrag:z\n", "a=ice-ufrag:x:y\na=ice-pwd:z\n"} {
		if _, _, err := iceCredentials(sdp); err == nil {
			t.Fatalf("accepted %q", sdp)
		}
	}
	var lines strings.Builder
	for i := 0; i <= maxCandidates; i++ {
		fmt.Fprintf(&lines, "a=candidate:1 1 udp 1 127.0.0.1 %d typ host\n", 1000+i)
	}
	if _, _, err := rewriteCandidates(lines.String(), "127.0.0.1", 1234); err == nil {
		t.Fatal("accepted excessive candidates")
	}
}

func TestICELiteFallbackAndNomination(t *testing.T) {
	open := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	client, first, second, attacker := open(), open(), open(), open()
	r, err := newIceRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	r.configure([]net.UDPAddr{*client.LocalAddr().(*net.UDPAddr)}, []net.UDPAddr{*first.LocalAddr().(*net.UDPAddr), *second.LocalAddr().(*net.UDPAddr)}, "c", "client-secret", "s", "server-secret")
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.port()}
	read := func(c *net.UDPConn) []byte {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 2048)
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		return buf[:n]
	}
	check := makeCheck("s:c", "server-secret", 1, false)
	_, _ = client.WriteToUDP(check, dst)
	_ = read(first)
	_ = read(second)
	// Neither an untracked source nor an invalid MAC can establish a path.
	_, _ = attacker.WriteToUDP(iceResponse(check, "server-secret"), dst)
	_, _ = first.WriteToUDP(iceResponse(check, "wrong"), dst)
	_ = client.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := client.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Fatal("forged response was forwarded")
	}
	_, _ = client.WriteToUDP([]byte("not-yet"), dst)
	_ = first.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := first.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Fatal("forged response selected a path")
	}
	_, _ = first.WriteToUDP(iceResponse(check, "server-secret"), dst)
	_ = read(client)
	_, _ = client.WriteToUDP([]byte("first"), dst)
	if got := string(read(first)); got != "first" {
		t.Fatalf("first path: %q", got)
	}
	// A new controlling nomination fans out even after a provisional success.
	check = makeCheck("s:c", "server-secret", 2, true)
	_, _ = client.WriteToUDP(check, dst)
	_ = read(first)
	_ = read(second)
	_, _ = second.WriteToUDP(iceResponse(check, "server-secret"), dst)
	_ = read(client)
	_, _ = client.WriteToUDP([]byte("second"), dst)
	if got := string(read(second)); got != "second" {
		t.Fatalf("nominated path: %q", got)
	}
	// A late, non-nominated success cannot displace the nominated pair.
	old := makeCheck("s:c", "server-secret", 1, false)
	_, _ = first.WriteToUDP(iceResponse(old, "server-secret"), dst)
	_, _ = client.WriteToUDP([]byte("still-second"), dst)
	if got := string(read(second)); got != "still-second" {
		t.Fatalf("late response moved path: %q", got)
	}
}

func TestEarlyUpstreamCheckBeforeAnswer(t *testing.T) {
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var port int
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "a=candidate:") {
				fields := strings.Fields(line)
				_, _ = fmt.Sscanf(fields[5], "%d", &port)
			}
		}
		_, _ = peer.WriteToUDP(makeCheck("c:s", "client-secret", 7, true), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		time.Sleep(30 * time.Millisecond)
		_, _ = fmt.Fprintf(w, "v=0\na=ice-ufrag:s\na=ice-pwd:server-secret\na=candidate:1 1 udp 1 127.0.0.1 %d typ host\n", peer.LocalAddr().(*net.UDPAddr).Port)
	}))
	defer upstream.Close()
	s, err := New(Config{RemoteURL: upstream.URL, MediaBind: "127.0.0.1:0", ClientAdvertiseAddr: "127.0.0.1", UpstreamAdvertiseAddr: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.closeRelays()
	offer := fmt.Sprintf("v=0\na=ice-ufrag:c\na=ice-pwd:client-secret\na=candidate:1 1 udp 1 127.0.0.1 %d typ host\n", client.LocalAddr().(*net.UDPAddr).Port)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/v1/join/42", strings.NewReader(offer)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, src, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(makeCheck("c:s", "client-secret", 7, true)) {
		t.Fatal("early check was altered")
	}
	_, _ = client.WriteToUDP(iceResponse(buf[:n], "client-secret"), src)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := peer.ReadFromUDP(buf); err != nil {
		t.Fatalf("ICE-lite response not forwarded: %v", err)
	}
}

func TestTransactionLimitsAndExpiry(t *testing.T) {
	r, err := newIceRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	c := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}
	u := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002}
	r.configure([]net.UDPAddr{*c}, []net.UDPAddr{*u}, "c", "client-secret", "s", "server-secret")
	r.mu.Lock()
	for i := 0; i < maxTransactions; i++ {
		r.stunTokens, r.fanoutTokens = stunBurst, fanoutBurst
		p := makeCheck("s:c", "server-secret", byte(i), false)
		r.handlePacket(p, c)
		if i == 0 {
			r.handlePacket(makeCheck("s:c", "server-secret", 0, true), c)
			if len(r.transactions) != 1 || r.transactions[0].nominated {
				t.Fatal("transaction ID collision changed nomination")
			}
		}
	}
	if len(r.transactions) != maxTransactions-maxCandidates {
		t.Fatalf("transactions: %d", len(r.transactions))
	}
	r.pruneTransactions(time.Now().Add(transactionTTL + time.Second))
	if len(r.transactions) != 0 {
		t.Fatal("expired transactions retained")
	}
	r.mu.Unlock()
}

func TestEarlyChecksBoundedAndUsernameRechecked(t *testing.T) {
	r, err := newIceRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	r.configureOffer([]net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 40001}}, "c", "client-secret")
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002}
	r.mu.Lock()
	for i := 0; i < maxEarlyChecks+5; i++ {
		r.handlePacket(makeCheck("c:wrong", "client-secret", byte(i), false), src)
	}
	if len(r.early) != maxEarlyChecks {
		t.Fatalf("early checks: %d", len(r.early))
	}
	r.mu.Unlock()
	r.configureAnswer([]net.UDPAddr{*src}, "s", "server-secret")
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.early) != 0 || len(r.transactions) != 0 {
		t.Fatal("early wrong-username checks were forwarded")
	}
}

func TestNominationAndRetransmissionAtCapacity(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	r, err := newIceRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41000}
	candidates := make([]net.UDPAddr, maxCandidates)
	for i := range candidates {
		candidates[i] = net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42000 + i}
	}
	candidates[maxCandidates-1] = *peer.LocalAddr().(*net.UDPAddr)
	r.configure([]net.UDPAddr{*client}, candidates, "c", "client-secret", "s", "server-secret")
	r.mu.Lock()
	for i := 0; i < 8; i++ {
		r.stunTokens, r.fanoutTokens = stunBurst, fanoutBurst
		r.handlePacket(makeCheck("s:c", "server-secret", byte(i), false), client)
	}
	if len(r.transactions) != maxTransactions-maxCandidates {
		t.Fatalf("ordinary checks consumed nomination reserve: %d", len(r.transactions))
	}
	nomination := makeCheck("s:c", "server-secret", 10, true)
	r.stunTokens, r.fanoutTokens = stunBurst, fanoutBurst
	r.handlePacket(nomination, client)
	if len(r.transactions) != maxTransactions {
		t.Fatalf("nomination did not fill reserved entries: %d", len(r.transactions))
	}
	// Remove the first destination of this nomination while keeping the table
	// full, so a retransmission must skip it and reach the final destination.
	for i, tx := range r.transactions {
		if tx.id[11] == 10 && tx.destination.String() == candidates[0].String() {
			r.transactions[i] = iceTransaction{id: [12]byte{1}, source: cloneUDP(client), destination: cloneUDP(client), created: time.Now()}
			break
		}
	}
	r.stunTokens, r.fanoutTokens = stunBurst, fanoutBurst
	r.handlePacket(nomination, client)
	// A new nomination must also be admitted when nominations fill the table.
	next := makeCheck("s:c", "server-secret", 11, true)
	r.stunTokens, r.fanoutTokens = stunBurst, fanoutBurst
	r.handlePacket(next, client)
	var found bool
	for _, tx := range r.transactions {
		if tx.id[11] == 11 && tx.destination.String() == candidates[maxCandidates-1].String() {
			found = true
		}
	}
	if !found || len(r.transactions) != maxTransactions {
		t.Fatal("new nomination not admitted at capacity")
	}
	r.mu.Unlock()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	count := 0
	for count < 2 {
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("nomination retransmission not delivered: %v", err)
		}
		if string(buf[:n]) == string(nomination) {
			count++
		}
	}
	_, _ = peer.WriteToUDP(iceResponse(next, "server-secret"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.port()})
	deadline := time.Now().Add(time.Second)
	for {
		r.mu.Lock()
		selected := r.nominated && r.upstream != nil && r.upstream.String() == peer.LocalAddr().String()
		r.mu.Unlock()
		if selected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nomination response did not select path")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCandidateDeduplicationAndFanoutRate(t *testing.T) {
	line := "a=candidate:1 1 udp 1 127.0.0.1 1234 typ host\n"
	_, candidates, err := rewriteCandidates(strings.Repeat(line, maxCandidates+1), "127.0.0.1", 5678)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("duplicate candidates: %d, %v", len(candidates), err)
	}
	if _, _, err := rewriteCandidates(strings.Repeat(line, maxCandidateLines+1), "127.0.0.1", 5678); err == nil {
		t.Fatal("unbounded duplicate candidate lines accepted")
	}
	now := time.Now()
	tokens, last := fanoutBurst, now
	for i := 0; i < int(fanoutBurst-nominationReserve); i++ {
		if !takeTokens(&tokens, &last, now, fanoutRate, fanoutBurst, 1, nominationReserve) {
			t.Fatal("premature fanout limit")
		}
	}
	if takeTokens(&tokens, &last, now, fanoutRate, fanoutBurst, 1, nominationReserve) {
		t.Fatal("ordinary fanout exceeded budget")
	}
	for i := 0; i < int(nominationReserve); i++ {
		if !takeTokens(&tokens, &last, now, fanoutRate, fanoutBurst, 1, 0) {
			t.Fatal("nomination reserve unavailable")
		}
	}
	if takeTokens(&tokens, &last, now, fanoutRate, fanoutBurst, 1, 0) {
		t.Fatal("nomination exceeded burst")
	}
	if !takeTokens(&tokens, &last, now.Add(time.Second), fanoutRate, fanoutBurst, 1, 0) {
		t.Fatal("fanout budget did not refill")
	}
}

func TestDuplicateCandidatesSendOnlyOnce(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	r, err := newIceRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41000}
	addr := *peer.LocalAddr().(*net.UDPAddr)
	r.configure([]net.UDPAddr{*client}, []net.UDPAddr{addr, addr, addr}, "c", "client-secret", "s", "server-secret")
	r.mu.Lock()
	r.handlePacket(makeCheck("s:c", "server-secret", 1, false), client)
	if len(r.upstreamCandidates) != 1 || len(r.transactions) != 1 {
		t.Fatal("duplicate candidates retained")
	}
	r.mu.Unlock()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := peer.ReadFromUDP(make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := peer.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Fatal("duplicate check forwarded")
	}
}

func TestOrdinaryChecksProgressAtCapacity(t *testing.T) {
	r, err := newIceRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41000}
	candidates := make([]net.UDPAddr, maxCandidates)
	for i := range candidates {
		candidates[i] = net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42000 + i}
	}
	r.configure([]net.UDPAddr{*client}, candidates, "c", "client-secret", "s", "server-secret")
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < 9; i++ {
		r.stunTokens, r.fanoutTokens, r.knownTokens = stunBurst, fanoutBurst, knownBurst
		r.handlePacket(makeCheck("s:c", "server-secret", byte(i), false), client)
	}
	if len(r.transactions) != maxTransactions-maxCandidates {
		t.Fatalf("transaction count %d", len(r.transactions))
	}
	last := candidates[maxCandidates-1]
	var found bool
	for _, tx := range r.transactions {
		if tx.id[11] == 8 && tx.destination.String() == last.String() {
			found = true
		}
	}
	if !found {
		t.Fatal("new ordinary check did not reach late candidate")
	}
	check := makeCheck("s:c", "server-secret", 8, false)
	r.handlePacket(iceResponse(check, "server-secret"), &last)
	if r.upstream == nil || r.upstream.String() != last.String() {
		t.Fatal("late working candidate was not selected")
	}
	if len(r.transactions) != maxTransactions-maxCandidates-1 {
		t.Fatal("completed destination was not retired")
	}
}

func TestInvalidSTUNDoesNotConsumeVerifiedBudgets(t *testing.T) {
	r, err := newIceRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41000}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42000}
	attacker := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43000}
	r.configure([]net.UDPAddr{*client}, []net.UDPAddr{*peer}, "c", "client-secret", "s", "server-secret")
	r.mu.Lock()
	defer r.mu.Unlock()
	check := makeCheck("s:c", "server-secret", 9, false)
	r.handlePacket(check, client)
	invalid := makeCheck("s:c", "wrong", 1, false)
	for i := 0; i < int(unknownBurst)*2; i++ {
		r.handlePacket(invalid, attacker)
	}
	for i := 0; i < int(stunBurst)*2; i++ {
		r.handlePacket(iceResponse(check, "wrong"), peer)
	}
	if r.responseTokens != stunBurst {
		t.Fatal("invalid responses consumed verified response budget")
	}
	// An advertised source's authenticated check is independent of the unknown-source budget.
	r.handlePacket(makeCheck("s:c", "server-secret", 10, false), client)
	if len(r.transactions) != 2 {
		t.Fatal("invalid unknown-source flood blocked verified check")
	}
	// Outstanding verified responses use a separate budget even if the verified
	// request budget has been exhausted by a credential holder.
	r.stunTokens = 0
	r.handlePacket(iceResponse(check, "server-secret"), peer)
	if r.upstream == nil || r.upstream.String() != peer.String() {
		t.Fatal("invalid traffic blocked valid outstanding response")
	}
}
