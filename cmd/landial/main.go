// Command landial performs a full NetherNet LAN signaling dial to a discovery
// host and prints the answer's ICE candidates and any trickled candidates, so
// the advertised media addresses of a BDS can be inspected without a game
// client. The connection is closed before login.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
)

type sniffer struct{}

func (sniffer) NotifySignal(s *nethernet.Signal) bool {
	switch s.Type {
	case nethernet.SignalTypeAnswer:
		fmt.Println("ANSWER signal received; candidate lines:")
		printCandidates(s.Data)
	case nethernet.SignalTypeCandidate:
		fmt.Printf("TRICKLED candidate: %s\n", strings.TrimSpace(s.Data))
	case nethernet.SignalTypeError:
		fmt.Printf("ERROR signal: %s\n", strings.TrimSpace(s.Data))
	}
	return false
}

func printCandidates(sdp string) {
	found := false
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a=candidate:") || strings.HasPrefix(line, "c=IN IP") {
			fmt.Printf("  %s\n", line)
			found = true
		}
	}
	if !found {
		fmt.Println("  (no inline candidate lines)")
	}
}

func main() {
	var target string
	var waitSeconds int
	var allowIdentityless bool
	flag.StringVar(&target, "target", "127.0.0.1:7551", "UDP address of the NetherNet LAN host to dial")
	flag.IntVar(&waitSeconds, "wait", 5, "seconds to wait for discovery before dialing")
	flag.BoolVar(&allowIdentityless, "allow-identityless", false, "accept answers without an a=identity assertion")
	flag.Parse()

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	addr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve:", err)
		os.Exit(1)
	}
	listener, err := (discovery.ListenConfig{BroadcastAddress: addr, Log: quiet}).Listen("0.0.0.0:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer listener.Close()
	stop := listener.Notify(sniffer{})
	defer stop()

	deadline := time.Now().Add(time.Duration(waitSeconds) * time.Second)
	var ids []uint64
	for time.Now().Before(deadline) {
		for id := range listener.Responses() {
			ids = append(ids, id)
		}
		if len(ids) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(ids) == 0 {
		fmt.Println("no discovery responses")
		os.Exit(1)
	}
	fmt.Printf("dialing network ID %d via LAN signaling...\n", ids[0])

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := (nethernet.Dialer{Log: quiet, AllowIdentitylessServer: allowIdentityless}).DialContext(ctx, strconv.FormatUint(ids[0], 10), listener)
	if err != nil {
		fmt.Println("dial result: failed:", err)
		os.Exit(1)
	}
	fmt.Println("dial result: CONNECTED (WebRTC data channel open; closing before login)")
	_ = conn.Close()
}
