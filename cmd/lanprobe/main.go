// Command lanprobe sends NetherNet LAN discovery requests to a host and prints
// the ServerData advertisement it returns. It verifies that a NetherNet-capable
// server (Bedrock dedicated server or game client host) is reachable on UDP
// 7551 and shows the identity/auth fields it advertises.
package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
)

type signalLogger struct{}

func (signalLogger) NotifySignal(s *nethernet.Signal) bool {
	fmt.Printf("signal from %s (conn %d): type %s, %d bytes\n", s.NetworkID, s.ConnectionID, s.Type, len(s.Data))
	return false
}

func main() {
	var target string
	var wait time.Duration
	flag.StringVar(&target, "target", "127.0.0.1:7551", "UDP address of the NetherNet LAN host to probe")
	flag.DurationVar(&wait, "wait", 3*time.Second, "how long to wait for discovery responses")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		log.Fatalf("resolve target: %v", err)
	}
	l, err := (discovery.ListenConfig{
		BroadcastAddress: addr,
		Log:              slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}).Listen("0.0.0.0:0")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	stop := l.Notify(signalLogger{})
	defer stop()
	defer l.Close()

	fmt.Printf("probing %s (our network ID %s) for %s...\n", target, l.NetworkID(), wait)
	time.Sleep(wait)

	resp := l.Responses()
	if len(resp) == 0 {
		fmt.Println("no discovery responses")
		os.Exit(1)
	}
	for id, data := range resp {
		var sd discovery.ServerData
		if err := sd.UnmarshalBinary(data); err != nil {
			fmt.Printf("network ID %d: raw %d bytes, decode error: %v\n", id, len(data), err)
			continue
		}
		fmt.Printf("network ID %d:\n", id)
		fmt.Printf("  server name:   %s\n", sd.ServerName)
		fmt.Printf("  level:         %s\n", sd.LevelName)
		fmt.Printf("  protocol:      %d (%s)\n", sd.Protocol, sd.Version)
		fmt.Printf("  players:       %d/%d, game type %d\n", sd.PlayerCount, sd.MaxPlayerCount, sd.GameType)
		fmt.Printf("  online auth:   %v\n", sd.AcceptsOnlineAuth)
		fmt.Printf("  self-signed:   %v\n", sd.AcceptsSelfSignedAuth)
		fmt.Printf("  nonce:         %q\n", sd.Nonce)
		fmt.Printf("  connection:    %d\n", sd.ConnectionType)
	}
}
