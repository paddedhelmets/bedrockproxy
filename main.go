// Command bedrockproxy advertises a remote Bedrock server to consoles on the LAN.
//
// It runs on a device on the consoles' LAN (Pi, mini-PC, always-on box) and does
// one or both of:
//
//   - LAN relay (--remote): answers RakNet broadcast pings with a spoofed pong and
//     relays the full game session to a remote server. Discovers on Xbox / PS / Win /
//     mobile. (Switch can't do LAN broadcast — use the DNS mode below for it.)
//   - Switch DNS mode (--dns-listen): runs a DNS server that resolves the Bedrock
//     "Featured Servers" hostnames to this proxy, so a Switch connecting to a featured
//     server is carried by the relay to the real remote server. Point each Switch's
//     DNS here, or the router/DHCP DNS here (LAN-wide, zero per-Switch config).
//
// See README.md and docs/reference-bedrock-lan-spoof.md.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/paddedhelmets/bedrockproxy/dns"
	"github.com/paddedhelmets/bedrockproxy/netherproxy"
	"github.com/paddedhelmets/bedrockproxy/proxy"
)

func main() {
	var (
		cfg             proxy.Config
		protocolText    string
		remoteSignalURL string
		mediaBind       string
		mediaClientIP   string
		mediaUpstreamIP string
		dnsListen       string
		dnsUpstream     string
		dnsTargetIP     string
	)
	flag.StringVar(&protocolText, "protocol", string(protocolNetherNet), "transport protocol: raknet or nethernet (default: nethernet)")
	// Relay / LAN mode.
	flag.StringVar(&cfg.BindAddr, "bind", ":19132", "listen address (UDP for RakNet, TCP for NetherNet signaling)")
	flag.StringVar(&cfg.RemoteAddr, "remote", "", "remote Bedrock server host:port (RakNet) or signaling URL/host:port (NetherNet)")
	flag.StringVar(&remoteSignalURL, "remote-signal-url", "", "upstream NetherNet signaling URL; defaults to --remote in NetherNet mode")
	flag.StringVar(&mediaBind, "media-bind", ":0", "NetherNet UDP relay bind address")
	flag.StringVar(&mediaClientIP, "media-client-address", "", "IPv4 address advertised to Bedrock clients for NetherNet UDP")
	flag.StringVar(&mediaUpstreamIP, "media-upstream-address", "", "IPv4 address advertised to the upstream NetherNet server for UDP")
	flag.StringVar(&cfg.Motd, "motd", "", "MOTD line 1; empty mirrors the remote server")
	flag.StringVar(&cfg.SubMotd, "sub-motd", "", "MOTD line 2; empty mirrors the remote server")
	flag.StringVar(&cfg.ProtocolVer, "protocol-version", "", "RakNet MOTD protocol version override; empty mirrors the remote server")
	flag.DurationVar(&cfg.RefreshEvery, "refresh", 60*time.Second, "re-probe remote MOTD interval; 0 = only at startup")
	flag.DurationVar(&cfg.SessionIdleTTL, "idle-timeout", 5*time.Minute, "drop idle console sessions after this long")
	// Switch DNS mode.
	flag.StringVar(&dnsListen, "dns-listen", "", "enable Switch/DNS mode: UDP address for the DNS server (e.g. :53). Empty = off.")
	flag.StringVar(&dnsUpstream, "dns-upstream", "1.1.1.1:53", "upstream resolver for non-pinned DNS queries")
	flag.StringVar(&dnsTargetIP, "dns-target-ip", "", "IP returned for pinned featured-server domains (the proxy's LAN IP); empty = auto-detect")
	flag.Parse()
	transport, err := parseTransportProtocol(protocolText)
	if err != nil {
		log.Fatal(err)
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if cfg.RemoteAddr == "" && remoteSignalURL == "" && dnsListen == "" {
		log.Fatal("must set at least one of --remote (LAN relay) or --dns-listen (Switch DNS mode)")
	}
	if transport == protocolNetherNet && dnsListen != "" {
		log.Fatal("--dns-listen is only supported with --protocol raknet")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	run := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				log.Printf("%s exited: %v", name, err)
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				cancel()
			}
		}()
	}

	// LAN relay: Xbox / PlayStation / Windows / mobile (and Switch once DNS points here).
	if transport == protocolRakNet && cfg.RemoteAddr != "" {
		srv, err := proxy.New(cfg)
		if err != nil {
			log.Fatalf("proxy init: %v", err)
		}
		run("relay", func() error { return srv.Serve(ctx) })
	}

	if transport == protocolNetherNet {
		remote := remoteSignalURL
		if remote == "" {
			remote = cfg.RemoteAddr
		}
		srv, err := netherproxy.New(netherproxy.Config{
			BindAddr:              cfg.BindAddr,
			RemoteURL:             remote,
			MediaBind:             mediaBind,
			ClientAdvertiseAddr:   mediaClientIP,
			UpstreamAdvertiseAddr: mediaUpstreamIP,
			Logger:                log.Default(),
		})
		if err != nil {
			log.Fatalf("nethernet init: %v", err)
		}
		run("nethernet signaling", func() error { return srv.Serve(ctx) })
	}

	// Switch DNS mode: pin featured-server domains to this proxy.
	if dnsListen != "" {
		var targetIP net.IP
		if dnsTargetIP != "" {
			targetIP = net.ParseIP(dnsTargetIP)
			if targetIP == nil {
				log.Fatalf("--dns-target-ip %q is not a valid IP", dnsTargetIP)
			}
		} else {
			ip, err := detectOutboundIP()
			if err != nil {
				log.Fatalf("auto-detect LAN IP for DNS: %v", err)
			}
			targetIP = ip
			log.Printf("auto-detected DNS target IP: %s (override with --dns-target-ip)", ip)
		}
		ds, err := dns.New(dnsListen, targetIP, dns.DefaultPinnedDomains, dnsUpstream, log.Default())
		if err != nil {
			log.Fatalf("dns init: %v", err)
		}
		run("dns", func() error { return ds.Serve(ctx) })
	}

	wg.Wait()
	if firstErr != nil {
		log.Fatalf("fatal: %v", firstErr)
	}
}

// detectOutboundIP returns the IPv4 this host uses to reach the internet — its LAN
// address, which is what devices on the LAN should connect to.
func detectOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "1.1.1.1:53")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("could not determine local address")
	}
	return ua.IP, nil
}
