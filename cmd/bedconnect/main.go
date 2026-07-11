// Command bedconnect dials a Bedrock server (or a bedrockproxy instance) at the
// RakNet layer to prove the FULL connection handshake completes end-to-end:
// OpenConnectionRequest 1/2 + ConnectionRequest + NewIncomingConnection.
//
// This is the validation that per-datagram relay testing can't cover: it confirms
// a real RakNet client establishes a session through the proxy, so consoles will.
//
//	go run ./cmd/bedconnect -addr 127.0.0.1:19130   # through the proxy
//	go run ./cmd/bedconnect -addr 127.0.0.1:19132   # directly to BDS (sanity)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	raknet "github.com/sandertv/go-raknet"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:19132", "target host:port")
	timeout := flag.Duration("timeout", 15*time.Second, "dial timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := raknet.DialContext(ctx, *addr)
	if err != nil {
		log.Fatalf("raknet dial %s FAILED: %v", *addr, err)
	}
	defer conn.Close()
	fmt.Printf("RakNet CONNECTED to %s (local=%s remote=%s)\n",
		*addr, conn.LocalAddr(), conn.RemoteAddr())
}
