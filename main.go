// Command bedrockproxy advertises a remote Bedrock server to consoles on the LAN.
//
// It runs on a device on the consoles' LAN (Pi, mini-PC, always-on box) and does
// one or both of:
//
//   - A RakNet LAN relay or a NetherNet signaling/media relay (--remote).
//   - Optional DNS (--dns-listen) pins selected featured-server hostnames to an
//     IPv4 address, and forwards other DNS queries to an upstream resolver.
//
// DNS redirection and signaling do not establish Switch compatibility; real-client
// discovery, ports, signaling and gameplay require separate validation.
//
// See README.md and docs/reference-bedrock-lan-spoof.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/df-mc/go-nethernet/discovery"
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
		lanDiscover     string
		lanUpstream     string
		lanMedia        string
		lanNetworkID    uint64
		lanProtocol     int
		lanVersion      string
		lanAuth         string
		dnsListen       string
		dnsUpstream     string
		dnsTargetIP     string
	)
	flag.StringVar(&protocolText, "protocol", string(protocolNetherNet), "transport: raknet or nethernet; legacy numeric values select raknet and override its MOTD protocol")
	// Relay / LAN mode.
	flag.StringVar(&cfg.BindAddr, "bind", ":19132", "listen address (UDP for RakNet, TCP for NetherNet signaling)")
	flag.StringVar(&cfg.RemoteAddr, "remote", "", "remote Bedrock server host:port (RakNet) or signaling URL/host:port (NetherNet)")
	flag.StringVar(&remoteSignalURL, "remote-signal-url", "", "upstream NetherNet signaling URL; defaults to --remote in NetherNet mode")
	flag.StringVar(&mediaBind, "media-bind", ":0", "NetherNet UDP relay bind address")
	flag.StringVar(&mediaClientIP, "media-client-address", "", "IPv4 address advertised to Bedrock clients for NetherNet UDP")
	flag.StringVar(&mediaUpstreamIP, "media-upstream-address", "", "IPv4 address advertised to the upstream NetherNet server for UDP")
	flag.StringVar(&lanDiscover, "lan-discover", "", "experimental: enable NetherNet LAN discovery/signaling bridge (UDP bind, e.g. :7551); empty = off")
	flag.StringVar(&lanUpstream, "lan-upstream", "", "experimental: tunnel LAN signaling to an upstream NetherNet LAN host (host[:port], default 7551) instead of HTTP translation; requires --lan-discover")
	flag.StringVar(&lanMedia, "lan-media", "direct", "experimental: LAN tunnel media mode: direct (clients reach upstream candidates) or assist (proxy relays media for unroutable candidates, e.g. Docker-bridged upstream)")
	flag.Uint64Var(&lanNetworkID, "lan-network-id", 0, "experimental: LAN discovery network ID; 0 = random")
	flag.IntVar(&lanProtocol, "lan-protocol", 0, "experimental: advertised Bedrock protocol; 0 = mirror the upstream signaling status")
	flag.StringVar(&lanVersion, "lan-version", "", "experimental: advertised Bedrock version; empty = mirror the upstream signaling status")
	flag.StringVar(&lanAuth, "lan-auth", "online", "experimental: advertised authentication policy: online, self-signed, or both")
	flag.StringVar(&cfg.Motd, "motd", "", "MOTD line 1; empty mirrors the remote server")
	flag.StringVar(&cfg.SubMotd, "sub-motd", "", "MOTD line 2; empty mirrors the remote server")
	flag.StringVar(&cfg.ProtocolVer, "protocol-version", "", "RakNet MOTD protocol version override; empty mirrors the remote server")
	flag.DurationVar(&cfg.RefreshEvery, "refresh", 60*time.Second, "re-probe remote MOTD interval; 0 = only at startup")
	flag.DurationVar(&cfg.SessionIdleTTL, "idle-timeout", 5*time.Minute, "drop idle console sessions after this long")
	// Optional DNS pinning, independent of relay transport.
	flag.StringVar(&dnsListen, "dns-listen", "", "enable DNS pinning: UDP listen address (e.g. :53); empty = off")
	flag.StringVar(&dnsUpstream, "dns-upstream", "1.1.1.1:53", "upstream resolver for non-pinned DNS queries")
	flag.StringVar(&dnsTargetIP, "dns-target-ip", "", "IP returned for pinned featured-server domains (the proxy's LAN IP); empty = auto-detect")
	flag.Parse()
	transport, version, err := resolveProtocol(protocolText, cfg.ProtocolVer)
	if err != nil {
		log.Fatal(err)
	}
	cfg.ProtocolVer = version

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if cfg.RemoteAddr == "" && remoteSignalURL == "" && dnsListen == "" {
		log.Fatal("must set at least one of --remote, --remote-signal-url, or --dns-listen")
	}
	if transport == protocolRakNet && remoteSignalURL != "" {
		log.Fatal("--remote-signal-url is only supported with --protocol nethernet")
	}
	if lanDiscover != "" && transport != protocolNetherNet {
		log.Fatal("--lan-discover is only supported with --protocol nethernet")
	}
	if lanUpstream != "" && lanDiscover == "" {
		log.Fatal("--lan-upstream requires --lan-discover")
	}
	if lanMedia != "direct" && lanMedia != "assist" {
		log.Fatal(`--lan-media must be "direct" or "assist"`)
	}
	if lanMedia == "assist" && lanUpstream == "" {
		log.Fatal("--lan-media assist requires --lan-upstream")
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

	// RakNet LAN relay.
	if transport == protocolRakNet && cfg.RemoteAddr != "" {
		srv, err := proxy.New(cfg)
		if err != nil {
			log.Fatalf("proxy init: %v", err)
		}
		run("relay", func() error { return srv.Serve(ctx) })
	}

	if transport == protocolNetherNet && (cfg.RemoteAddr != "" || remoteSignalURL != "") {
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
			MediaIdleTTL:          cfg.SessionIdleTTL,
			Logger:                log.Default(),
		})
		if err != nil {
			log.Fatalf("nethernet init: %v", err)
		}
		run("nethernet signaling", func() error { return srv.Serve(ctx) })

		if lanDiscover != "" && lanUpstream != "" {
			var assistIP net.IP
			if lanMedia == "assist" {
				if mediaClientIP == "" {
					log.Fatal("--lan-media assist requires --media-client-address")
				}
				assistIP = net.ParseIP(mediaClientIP)
				if assistIP == nil || assistIP.To4() == nil {
					log.Fatalf("--media-client-address %q is not an IPv4 address", mediaClientIP)
				}
			}
			tunnel, err := netherproxy.NewLANTunnel(netherproxy.TunnelConfig{
				BindAddr:     lanDiscover,
				UpstreamAddr: lanUpstream,
				MediaAssist:  lanMedia == "assist",
				AdvertiseIP:  assistIP,
				MediaBind:    mediaBind,
				MediaIdleTTL: cfg.SessionIdleTTL,
				Logger:       log.Default(),
			})
			if err != nil {
				log.Fatalf("lan-upstream init: %v", err)
			}
			go func() {
				<-ctx.Done()
				if err := tunnel.Close(); err != nil {
					log.Printf("lan tunnel close: %v", err)
				}
			}()
			log.Printf("lan tunnel active (network ID %s, experimental, trusted LAN only)", tunnel.NetworkID())
		} else if lanDiscover != "" {
			data, err := lanServerData(remote, lanAuth, lanProtocol, lanVersion)
			if err != nil {
				log.Fatalf("lan-discover init: %v", err)
			}
			bridge, err := netherproxy.NewLANBridge(netherproxy.LANConfig{
				BindAddr:  lanDiscover,
				NetworkID: lanNetworkID,
				Data:      data,
			}, srv)
			if err != nil {
				log.Fatalf("lan-discover init: %v", err)
			}
			go func() {
				<-ctx.Done()
				if err := bridge.Close(); err != nil {
					log.Printf("lan bridge close: %v", err)
				}
			}()
			log.Printf("lan discovery bridge up: %s (network ID %s, experimental, trusted LAN only)", lanDiscover, bridge.NetworkID())
		}
	}

	// Pin featured-server domains independently of the selected relay transport.
	if dnsListen != "" {
		var targetIP net.IP
		if dnsTargetIP != "" {
			targetIP = net.ParseIP(dnsTargetIP)
			if targetIP.To4() == nil {
				log.Fatalf("--dns-target-ip %q is not a valid IPv4 address", dnsTargetIP)
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

// netherNetStatus is the documented GET /v1/join response body.
type netherNetStatus struct {
	Name       string `json:"name"`
	Protocol   int32  `json:"protocol"`
	Version    string `json:"version"`
	Level      string `json:"level"`
	Players    int32  `json:"players"`
	MaxPlayers int32  `json:"maxPlayers"`
	GameType   int32  `json:"gameType"`
}

// lanServerData builds the LAN discovery advertisement from the upstream
// signaling status. protocolOverride/versionOverride (non-zero/non-empty)
// replace the mirrored values. auth is one of online, self-signed, or both.
func lanServerData(remoteURL, auth string, protocolOverride int, versionOverride string) (discovery.ServerData, error) {
	online, selfSigned := false, false
	switch auth {
	case "online":
		online = true
	case "self-signed":
		selfSigned = true
	case "both":
		online, selfSigned = true, true
	default:
		return discovery.ServerData{}, fmt.Errorf("invalid --lan-auth %q (want online, self-signed, or both)", auth)
	}
	if protocolOverride != 0 && versionOverride == "" || protocolOverride == 0 && versionOverride != "" {
		return discovery.ServerData{}, errors.New("override both --lan-protocol and --lan-version or neither")
	}
	status := netherNetStatus{Protocol: int32(protocolOverride), Version: versionOverride}
	if status.Protocol == 0 {
		url := remoteURL
		if !strings.Contains(url, "://") {
			url = "http://" + url
		}
		url = strings.TrimSuffix(url, "/") + "/v1/join"
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			return discovery.ServerData{}, fmt.Errorf("fetch upstream signaling status: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return discovery.ServerData{}, fmt.Errorf("upstream signaling status: HTTP %d", resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return discovery.ServerData{}, fmt.Errorf("read upstream signaling status: %w", err)
		}
		if err := json.Unmarshal(body, &status); err != nil {
			return discovery.ServerData{}, fmt.Errorf("parse upstream signaling status: %w", err)
		}
	}
	if status.Protocol <= 0 || status.Version == "" {
		return discovery.ServerData{}, errors.New("upstream signaling status lacks protocol/version; pass --lan-protocol and --lan-version")
	}
	return discovery.ServerData{
		ServerName:            status.Name,
		Protocol:              status.Protocol,
		Version:               status.Version,
		LevelName:             status.Level,
		PlayerCount:           status.Players,
		MaxPlayerCount:        status.MaxPlayers,
		GameType:              status.GameType,
		AcceptsOnlineAuth:     online,
		AcceptsSelfSignedAuth: selfSigned,
		ConnectionType:        4,
	}, nil
}
