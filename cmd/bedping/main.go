// Command bedping sends a RakNet unconnected ping and prints the pong.
//
// Test tool: pings any Bedrock server (or a bedrockproxy instance) and shows the
// advertised MOTD / protocol / version, so you can confirm what consoles will see.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/paddedhelmets/bedrockproxy/raknet"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:19132", "target host:port")
	timeout := flag.Duration("timeout", 3*time.Second, "wait for pong")
	flag.Parse()

	raddr, err := net.ResolveUDPAddr("udp4", *addr)
	if err != nil {
		log.Fatalf("resolve: %v", err)
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(*timeout)); err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write(raknet.BuildPing(time.Now().UnixMilli(), 0x1337)); err != nil {
		log.Fatalf("write ping: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("no pong from %s: %v", *addr, err)
	}
	pong, err := raknet.ParsePong(buf[:n])
	if err != nil {
		log.Fatalf("parse: %v", err)
	}
	fmt.Printf("pong from %s\n", *addr)
	fmt.Printf("  serverID : %d\n", pong.ServerID)
	fmt.Printf("  magic OK : %v\n", pong.MagicOK)
	fmt.Printf("  protocol : %s\n", pong.Motd.ProtocolVersion)
	fmt.Printf("  version  : %s\n", pong.Motd.VersionName)
	fmt.Printf("  players  : %s / %s\n", pong.Motd.PlayerCount, pong.Motd.MaxPlayers)
	fmt.Printf("  motd     : %s\n", pong.Motd.Motd)
	fmt.Printf("  sub-motd : %s\n", pong.Motd.SubMotd)
	fmt.Printf("  raw      : %s\n", pong.Motd.String())
}
