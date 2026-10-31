# bedrockproxy

Relay a remote Minecraft Bedrock server to clients on your local network. RakNet
mode advertises a LAN game; the separate Switch DNS mode redirects featured-server
lookups. NetherNet mode relays HTTP signaling and UDP media, and can optionally
bridge NetherNet LAN discovery (`--lan-discover`, experimental) so LAN clients
find the proxy without manual server entry.

This is a self-hosted, ad-free replacement for the **BedrockTogether** phone app,
run as a small persistent service on a device that lives on the same LAN as the
consoles (a Raspberry Pi, mini-PC, or always-on box). One static binary.

## Why this exists

Consoles lock Bedrock's "Servers" tab to a Microsoft-curated list. The only way
for a Switch/PS5/Xbox to reach *your* server is via the **LAN / Friends** tab.
BedrockTogether solves that by running on a phone on the family Wi-Fi and
spoofing a LAN game. `bedrockproxy` does the same job, but:

- runs **persistently** on a cheap box on the LAN (no phone to keep charged/open),
- is a single cross-compiled binary with **no ads and no telemetry**,
- is configurable and scriptable.

## How it works

The proxy supports two transport modes. `--protocol nethernet` is the default and
relays NetherNet HTTP signaling plus an encrypted ICE/UDP media relay. `--protocol
raknet` retains the legacy UDP behavior. NetherNet identity, DTLS, SCTP, and
Bedrock payloads remain end-to-end opaque; only SDP candidate addresses and UDP
packets are relayed.

In RakNet mode, the proxy listens on the Bedrock port (UDP `19132`) on the LAN.
For each console that probes the LAN it does two things:

1. **Spoofed discovery** — answers RakNet `ID_UNCONNECTED_PING` broadcasts with a
   `PONG` whose MOTD advertises your chosen remote server (it mirrors the remote's
   real protocol/version so consoles never reject it as "outdated").
2. **Transparent relay** — for every other datagram (the actual RakNet game
   session: connection handshake, framed data, ECDH/AES handshake bytes), it
   shuttles bytes between the console and the remote server verbatim.

3. **NetherNet relay** (Bedrock 26.50+ servers; 26.60+ clients speak *only*
   NetherNet) — on **TCP** `19132` it relays the HTTP signaling (`GET /v1/join`,
   `POST /v1/join/{id}`) to the remote, rewriting the WebRTC ICE candidates so the
   console and the server each see the proxy as the other's only address. Media
   (STUN/DTLS/SCTP) then arrives on the same UDP `19132` socket, is matched to its
   session by ICE username, and is shuttled to the server's media port. DTLS is
   end-to-end, so the server's Xbox auth is untouched.

A relay is *required*, not optional: a RakNet pong has no address field, so the
console connects back to the **source IP of the pong** — i.e. the proxy — which
must then forward the traffic to the real server. Verified across the original
RakNet, JRakNet, go-raknet, and CloudburstMC. See
[`docs/reference-bedrock-lan-spoof.md`](docs/reference-bedrock-lan-spoof.md) for
the byte-exact protocol spec.

```
 family LAN (e.g. sibling's Wi-Fi)                  internet
 ──────────────────────────────────                ────────────────
 console ──UDP──> bedrockproxy:19132 ──UDP/NAT──>  remote Bedrock server
 (Switch/Xbox/PS5)  │ spoofs LAN pong              (your VPS / dad's box)
                    └ relays game datagrams both ways, per console
```

> **Firewall:** open **UDP and TCP** `19132` on the proxy (TCP carries NetherNet
> signaling), and make sure the proxy can reach the server's TCP `19132` and its
> NetherNet UDP media port (see `server-udp-ports` in the server's
> `server.properties`; the proxy logs the port it relays to on each join).

> **Important:** the proxy must run on a device **on the target LAN**. A cloud
> box that isn't on the consoles' broadcast domain can't do LAN discovery —
> physics, not a limitation of this tool.

## Build

Requires Go 1.25+ when building from source. GitHub Actions also builds downloadable
artifacts for each successful run; open the commit's **Actions** run and download
the `bedrockproxy-<commit>` artifact. It contains platform binaries and
`SHA256SUMS`; repository access is required.

```sh
go build -o bedrockproxy .          # the proxy
go build -o bedping ./cmd/bedping   # the ping/debug client
```

## Run

```sh
# NetherNet signaling relay (default)
./bedrockproxy --protocol nethernet --bind :19132 \
  --remote-signal-url http://dad.example.com:19132 \
  --media-bind :0 \
  --media-client-address 192.168.1.20 \
  --media-upstream-address 100.100.100.2

# Legacy RakNet relay
./bedrockproxy --protocol raknet --remote dad.example.com:19132 --motd "Granddad's World"
```

Flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--protocol` | `nethernet` | `nethernet` signaling relay or legacy `raknet` UDP relay. |
| `--remote` | *(empty)* | RakNet `host:port`, or NetherNet signaling URL/host:port; required for a relay unless NetherNet `--remote-signal-url` is set. |
| `--remote-signal-url` | *(empty)* | Explicit NetherNet upstream signaling URL; overrides `--remote`. |
| `--bind` | `:19132` | TCP signaling bind in NetherNet mode; UDP bind in RakNet mode. |
| `--media-bind` | `:0` | UDP relay bind for NetherNet media. Each session needs its own port; a fixed port prevents concurrent sessions. Port ranges are not supported. |
| `--media-client-address` | *(required)* | IPv4 address visible to Bedrock clients. |
| `--media-upstream-address` | *(required)* | IPv4 address visible to the upstream BDS. |
| `--lan-discover` | *(off)* | Experimental: UDP bind for the NetherNet LAN discovery/signaling bridge (e.g. `:7551`). Trusted LAN only; unvalidated on console hardware. |
| `--lan-network-id` | *(random)* | Experimental: LAN discovery network ID. |
| `--lan-protocol` | *(mirror)* | Experimental: advertised protocol override. |
| `--lan-version` | *(mirror)* | Experimental: advertised version override. |
| `--lan-auth` | `online` | Experimental: advertised auth policy: `online`, `self-signed`, or `both`. |
| `--motd` | *(mirror remote)* | MOTD line 1 shown in the server list. |
| `--sub-motd` | *(mirror remote)* | MOTD line 2 (subtitle). |
| `--protocol-version` | *(mirror remote)* | Legacy RakNet MOTD protocol override. |
| `--refresh` | `60s` | Re-probe the remote's MOTD (player counts, version) every N; `0` = once. |
| `--idle-timeout` | `5m` | Drop idle RakNet sessions or NetherNet media relays after this long. NetherNet treats `0` as its default of `5m`. |
| `--dns-listen` | *(off)* | Enable **Switch mode**: UDP address for the DNS server (e.g. `:53`). Empty = off. |
| `--dns-target-ip` | *(auto)* | IP returned for pinned featured-server domains (the proxy's LAN IP). |
| `--dns-upstream` | `1.1.1.1:53` | Upstream resolver for non-pinned queries (keeps the rest of the LAN resolving). |

RakNet mode mirrors the remote protocol/version by default, so as
long as your consoles and the remote run the same Bedrock version they'll join
cleanly.

NetherNet mode requires a compatible HTTP signaling endpoint; a normal RakNet
Bedrock server address is not automatically such an endpoint. Set the two media
addresses to reachable proxy IPv4 addresses for the client and upstream sides,
and allow the dynamically allocated UDP ports through any firewalls/NAT. The
relay rewrites SDP candidates but does not guarantee NAT traversal. Real-console
interoperability requires validation in the target environment; a mobile client
has joined through the relay, but console discovery via `--lan-discover` is
experimental and unverified on hardware.

Treat the NetherNet signaling listener as trusted-LAN-only: it is unauthenticated,
and a signaling client can direct UDP checks to supplied candidate addresses. Do not
expose it to the public internet. A wildcard media bind also relies on OS routing
to choose the source address; on a multihomed host, verify that packets leave
with the addresses advertised to each peer.

**Migration:** The CLI now defaults to NetherNet. Existing RakNet commands must
add `--protocol raknet`, including DNS mode. The old numeric `--protocol 2169`
still selects RakNet and overrides its advertised protocol; prefer
`--protocol raknet --protocol-version 2169`. An updated systemd unit defaults
missing `PROTOCOL` to RakNet for existing environment files; new example
environment files explicitly select NetherNet. Review the environment before
restarting, especially if replacing it with the new example.

## Deploy to a family LAN (the common case)

On a Pi / mini-PC on the consoles' network:

```sh
# Download the matching build from https://github.com/paddedhelmets/bedrockproxy/releases
# (or build from source: GOOS=linux GOARCH=arm64 go build .)
./bedrockproxy --protocol raknet --remote dad.example.com:19132 --motd "Granddad's World"
```

Or as a systemd service (see `deploy/README.md`). LAN discovery depends on the
client and network; console hardware validation remains outstanding.

## Nintendo Switch (DNS mode)

The Switch can't be reached by LAN broadcast (Nintendo restricts it to its own
Local Wireless radio). It can, however, connect to the **Featured Servers** list —
whose hostnames it resolves via DNS. The DNS mode resolves those hostnames to the
proxy, so a Switch clicking a featured server connects to the proxy and is relayed
to your remote server, exactly like the other consoles.

Run the proxy with DNS enabled (needs UDP 53; the systemd unit grants
`CAP_NET_BIND_SERVICE`):

```sh
sudo ./bedrockproxy --protocol raknet --remote dad.example.com:19132 --dns-listen :53
```

Then point Switches at the DNS — **two ways, same proxy**:

- **Per-Switch:** set each Switch's primary DNS to the proxy's LAN IP (secondary
  `1.1.1.1`). Most control, per device.
- **LAN-wide (zero per-Switch config):** set the router's DNS (or the DHCP-advertised
  DNS) to the proxy's LAN IP. Every Switch on the LAN is redirected automatically;
  non-pinned queries are forwarded upstream so the rest of the LAN keeps working.

The pinned domains are the five current Bedrock featured servers (`hivebedrock.network`,
`play.inpvp.net`, `mco.lbsg.net`, `play.galaxite.net`, `play.enchanted.gg`). If your
family hit "Switch shows Coming Soon / can't connect", the usual culprits are IPv6
bypassing the IPv4 DNS (disable IPv6 on the router, or the Switch falls back to an
IPv6 resolver you don't control) — set the Switch's DNS explicitly as a fallback.

## Platform support & caveats

| Platform | LAN relay |
|----------|-----------|
| Win10/11, iOS, Android | RakNet LAN discovery; can also add servers manually |
| Xbox | RakNet LAN discovery, real-console validation pending |
| PS4 / PS5 | RakNet LAN discovery, real-console validation pending |
| **Switch** | RakNet DNS redirect (`--dns-listen :53`), real-console validation pending |

RakNet mode responds to discovery pings on UDP port 19132; it does not proactively
broadcast announcements. DNS redirection depends on featured-server hostnames and
client behavior, which may change.

## Roadmap

- [x] Spoofed RakNet pong (discovery)
- [x] Transparent UDP relay (full game session)
- [x] Remote MOTD mirroring
- [x] **Switch DNS mode** — featured-server redirect, per-Switch or LAN-wide (router DNS)
- [x] Cross-compiled release binaries (linux arm64/amd64, macOS, windows)
- [x] NetherNet relay (signaling + ICE candidate rewrite + UDP media), for 26.60+ clients
- [ ] NetherNet LAN discovery (UDP 7551) — until then, Xbox/PS use DNS mode too
- [ ] Proactive LAN pong broadcaster (faster discovery for some clients)
- [ ] Real-console hardware validation (Switch via DNS; Xbox/PS via LAN)
- [ ] Optional web/TUI status (sessions, bandwidth)

## License

MIT — see [LICENSE](LICENSE). Matches the RakNet libraries it interoperates with.
