# Bedrock LAN-Spoof Proxy — Protocol & Design Reference

Verified 2026-07-11 against the source of pmmp/RakLib, CloudburstMC/Network &
Protocol, sandertv/go-raknet, whirvis/JRakNet, facebookarchive/RakNet, and
GeyserMC/Geyser. Every wire-format fact below is byte-exact and source-confirmed;
anything still open is explicitly marked **UNCONFIRMED**.

## What this does

Makes a *remote* Bedrock server appear as a **LAN game** to every Bedrock client on
a LAN, so locked-down consoles (Xbox / PlayStation / Switch) can join it from their
Friends / LAN tab without paying for Realms or using a featured server — an ad-free,
self-hosted replacement for the **BedrockTogether** phone app, run as a persistent
service on a device on the LAN.

## Two transports, one proxy

The proxy supports two discovery paths to the same transparent relay:

1. **LAN broadcast (Xbox / PS / Win / mobile):** the proxy answers RakNet
   `ID_UNCONNECTED_PING` broadcasts with a spoofed pong advertising the remote
   server, then relays the full RakNet game session to it.
2. **DNS redirect (Nintendo Switch):** the Switch can't do LAN broadcast (Nintendo
   restricts it to its own Local Wireless radio). It can only reach custom servers
   through its curated **Featured Servers** list, whose hostnames it resolves via
   DNS. The proxy runs a DNS server that resolves those hostnames to itself, so a
   Switch clicking a featured server connects to the proxy and is relayed to the
   remote — same relay, different discovery path.

## Why a relay is mandatory

A RakNet `ID_UNCONNECTED_PONG` carries **no address field**. The client connects
back to the **UDP source IP:port of the received pong** (the proxy), not to anything
in the payload. Confirmed in facebookarchive/RakNet `RakPeer.cpp`,
JRakNet `DiscoveryHandler`, go-raknet `listener.go`, CloudburstMC `RakNetServer`.

So to reach a *remote* server, the proxy must proxy the actual RakNet game UDP
between each console and the remote. The MOTD `ipv4Port`/`ipv6Port` fields are
display-only metadata and do **not** redirect the client.

## Why no Bedrock serverlist / TransferPacket (unlike BedrockConnect)

BedrockConnect runs a full Bedrock protocol server that presents a server-list menu
and emits a `TransferPacket`. It needs that because (a) it offers a *menu* of
servers and (b) its *public* instance can't afford to relay every client's game
traffic. We have a single fixed target and self-host, so DNS-redirect-to-proxy plus
the transparent relay is sufficient — and keeps the binary dependency-free. The
relay is agnostic to how the client discovered it.

# Wire format

## Transport & discovery

- UDP. Bedrock server port **19132** (IPv4), **19133** (IPv6).
- Discovery = **limited broadcast** to `255.255.255.255:19132` (not multicast, not
  subnet-directed). Client source port is ephemeral; `SO_BROADCAST` on the client
  socket. (The `224.0.2.60:4445` multicast group is **Java Edition only**.)

## ID_UNCONNECTED_PING `0x01` — 33 bytes

```
0      1    packet ID        = 0x01  (or 0x02 = "open connection" variant)
1      8    sendPingTime     int64 BIG-ENDIAN
9      16   MAGIC            (see below)
25     8    clientGUID       int64 BIG-ENDIAN
```
MAGIC sits **between** the two longs. Both `0x01` and `0x02` are answered with a pong.

## ID_UNCONNECTED_PONG `0x1c` — 35 + N bytes

```
0      1    packet ID        = 0x1c
1      8    pingTime         int64 BIG-ENDIAN (echoed from the ping)
9      8    serverId / GUID  int64 BIG-ENDIAN
17     16   MAGIC
33     2    userData length  uint16 BIG-ENDIAN, UNSIGNED
35     N    userData (MOTD)  UTF-8
```
**Asymmetry:** in the pong, MAGIC comes **after** both longs; in the ping it sits
**between** them. No NUL terminator on the MOTD.

## MAGIC — 16 bytes

```
00 FF FF 00 FE FE FE FE FD FD FD FD 12 34 56 78
```
Receivers validate all 16 bytes exactly. Always emit the canonical value.

## MOTD (userData) — 12 fields, `;`-delimited, trailing `;`

Authoritative builder/parser: `CloudburstMC/Protocol` `BedrockPong.java`.

```
MCPE;<motd1>;<protocolVersion>;<versionName>;<playerCount>;<maxPlayers>;<serverId>;<motd2>;<gameType>;<nintendoLimited>;<ipv4Port>;<ipv6Port>;
```

| # | field | notes |
|---|-------|-------|
| 1 | edition | `MCPE` (Bedrock), `MEE` (Education) |
| 2 | motd (line 1) | top line |
| 3 | protocolVersion | **CLIENT VALIDATES — gates connect** |
| 4 | version (name) | human string |
| 5 | playerCount | display |
| 6 | maximumPlayerCount | display |
| 7 | serverId | RakNet GUID, echoed in handshake |
| 8 | subMotd (line 2) | second line |
| 9 | gameType | display |
| 10 | nintendoLimited | **inverted**: `"1"` = NOT limited, `"0"` = limited |
| 11 | ipv4Port | display only |
| 12 | ipv6Port | display only |

Canonical example: `MCPE;Dedicated Server;1001;1.26.33;0;10;10090977620693818310;Bedrock level;Survival;1;19132;19133;`

This proxy mirrors the remote server's real protocol/version so clients never reject
the advertised server as "outdated".

## Featured-server domains (DNS mode)

The five hostnames a Switch resolves for its Featured Servers (from BedrockConnect's
`install-bind.sh`; CubeCraft opts out):

- `hivebedrock.network` (+ `geo.` prefix)
- `play.inpvp.net`
- `mco.lbsg.net`
- `play.galaxite.net`
- `play.enchanted.gg`

## Console notes (UNCONFIRMED behaviour, confirmed protocol)

All consoles use the same RakNet discovery protocol; differences are platform-layer:

| Platform | "Add server" UI | LAN broadcast | Notes |
|----------|-----------------|---------------|-------|
| Win/iOS/Android | yes | works | — |
| Xbox | no | works | needs Xbox Game Pass Core |
| PS4/PS5 | no | works | PS5 LAN-detection quirk (MCPE-239057) |
| Switch | no | **no** (Nintendo Local Wireless only) | use DNS mode |

## Bedrock encryption (FYI)

Custom ECDH on secp384r1, ANSI X9.63 KDF, AES-256. The transparent relay never touches
this — the handshake bytes flow through verbatim.

## Prior art / libraries

- **phantom** (jhead, Go) — the canonical LAN-spoof this project is modelled on.
- **BedrockTogether** (Extollite) — the commercial phone app being replaced (LAN only).
- **BedrockConnect** (Pugmatt) — DNS-hijack + serverlist/transfer for consoles/Switch.
- **gophertunnel** / **sandertv/go-raknet** / **df-mc/dragonfly** (MIT) — Go RakNet/Bedrock reference implementations.
- **MCXboxBroadcast** — Xbox Live friend-bot method (alternative Switch path).

---
*Living document. Protocol facts are stable; update the featured-server domain list
and protocol-version table when Mojang changes them.*
