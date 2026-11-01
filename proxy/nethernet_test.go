package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paddedhelmets/bedrockproxy/nethernet"
)

// freePort returns a port free for both TCP and UDP on 127.0.0.1.
func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		p := u.LocalAddr().(*net.UDPAddr).Port
		l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", p))
		u.Close()
		if err == nil {
			l.Close()
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}

func stunCheck(user string) []byte {
	attr := make([]byte, 4, 4+len(user)+3)
	binary.BigEndian.PutUint16(attr[0:2], 0x0006)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(user)))
	attr = append(attr, user...)
	for len(attr)%4 != 0 {
		attr = append(attr, 0)
	}
	b := make([]byte, 20, 20+len(attr))
	binary.BigEndian.PutUint16(b[0:2], 0x0001)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(b[4:8], 0x2112A442)
	return append(b, attr...)
}

// TestNetherNetRelay drives a full signaling + media exchange through the proxy
// against a fake NetherNet BDS (HTTP signaling + UDP echo media socket).
func TestNetherNetRelay(t *testing.T) {
	// Fake server media socket: echoes, and remembers who it heard from.
	media, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer media.Close()
	mediaPort := media.LocalAddr().(*net.UDPAddr).Port
	heardFrom := make(chan *net.UDPAddr, 4)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := media.ReadFromUDP(buf)
			if err != nil {
				return
			}
			heardFrom <- from
			_, _ = media.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()

	// Fake signaling endpoint. The answer advertises a Docker-style container IP
	// to check the proxy substitutes the remote IP.
	offers := make(chan string, 1)
	sigLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/join", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"name":"Real","protocol":2225,"version":"1.26.61","level":"Farmville","players":1,"maxPlayers":10,"gameType":0}`)
	})
	mux.HandleFunc("POST /v1/join/{id}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		offers <- string(b)
		w.Header().Set("Content-Type", "application/sdp")
		fmt.Fprintf(w, "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n"+
			"a=ice-ufrag:srvU\r\na=ice-pwd:p\r\na=candidate:1 1 UDP 1 172.17.0.2 %d typ host\r\na=end-of-candidates\r\n", mediaPort)
	})
	hs := &http.Server{Handler: mux}
	go hs.Serve(sigLn)
	defer hs.Close()

	port := freePort(t)
	srv, err := New(Config{
		BindAddr:   fmt.Sprintf("127.0.0.1:%d", port),
		RemoteAddr: sigLn.Addr().String(),
		Motd:       "Spoofed",
		Logger:     log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	// Server info passes through with the --motd override.
	resp, err := http.Get(base + "/v1/join")
	if err != nil {
		t.Fatal(err)
	}
	info, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(info), `"name":"Spoofed"`) || !strings.Contains(string(info), `"level":"Farmville"`) {
		t.Fatalf("join info = %s", info)
	}

	// Signal an offer.
	offer := "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:cliU\r\na=ice-pwd:q\r\n" +
		"a=candidate:1 1 UDP 1 192.168.7.50 50000 typ host\r\na=end-of-candidates\r\n"
	resp, err = http.Post(base+"/v1/join/net123", "application/sdp", strings.NewReader(offer))
	if err != nil {
		t.Fatal(err)
	}
	ans, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("POST status %d: %s", resp.StatusCode, ans)
	}

	// Server saw the proxy's upstream socket as the client's only candidate.
	seen := nethernet.Parse(<-offers)
	if len(seen.Candidates) != 1 || seen.Candidates[0].IP != "127.0.0.1" || seen.Candidates[0].Port == 50000 {
		t.Fatalf("server saw offer candidates %+v", seen.Candidates)
	}
	// Console sees the proxy's LAN UDP port as the server's only candidate.
	got := nethernet.Parse(string(ans))
	if got.Ufrag != "srvU" || len(got.Candidates) != 1 || got.Candidates[0].IP != "127.0.0.1" || got.Candidates[0].Port != port {
		t.Fatalf("console got answer %+v", got)
	}

	// Media: STUN check from console binds the session and reaches the server
	// from the advertised upstream candidate; then non-STUN (DTLS) follows.
	console, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer console.Close()
	_ = console.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i, pkt := range [][]byte{stunCheck("srvU:cliU"), {0x16, 0xfe, 0xfd, 'h', 'i'}} {
		if _, err := console.Write(pkt); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		n, err := console.Read(buf)
		if err != nil {
			t.Fatalf("packet %d: no echo: %v", i, err)
		}
		if want := "echo:" + string(pkt); string(buf[:n]) != want {
			t.Fatalf("packet %d: echo mismatch", i)
		}
		if from := <-heardFrom; from.Port != seen.Candidates[0].Port {
			t.Fatalf("server heard from %s, offer said port %d", from, seen.Candidates[0].Port)
		}
	}

	// A check for an unknown session is dropped, not sent to the RakNet relay.
	stray, _ := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	defer stray.Close()
	stray.Write(stunCheck("nope:nope"))
	time.Sleep(100 * time.Millisecond)
	srv.sessionsMu.Lock()
	n := len(srv.sessions)
	srv.sessionsMu.Unlock()
	if n != 0 {
		t.Fatalf("stray STUN opened %d RakNet sessions", n)
	}

	// MOTD probe falls back to GET /v1/join when RakNet ping fails.
	m, err := srv.probeJoinInfo()
	if err != nil || m.Motd != "Real" || m.ProtocolVersion != "2225" || m.VersionName != "1.26.61" {
		t.Fatalf("probeJoinInfo = %+v, %v", m, err)
	}
}
