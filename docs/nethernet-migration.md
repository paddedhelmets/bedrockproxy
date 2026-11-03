# Bedrock 26.60 NetherNet Migration

## Finding

Bedrock 26.60 removed RakNet client support. `bedrockproxy` currently implements
RakNet discovery and a transparent RakNet UDP relay, so it cannot carry a 26.60
client session. Changing the advertised MOTD protocol number cannot fix this:
the client now expects NetherNet signaling followed by WebRTC data channels. HTTP
signaling and LAN discovery/signaling are distinct paths.

Evidence:

- Minecraft Wiki: https://minecraft.wiki/w/NetherNet
- Mojang protocol guide: https://mojang.github.io/bedrock-protocol-docs/guides/nether-net-onboarding-guide/
- Geyser migration guide: https://geysermc.org/blog/preparing-for-nethernet/

The legacy path remains healthy. On this host, the proxy's unit tests and build
pass, and a loopback proxy relays discovery to the local BDS 1.26.45 instance,
which reports protocol `2169`.

## Symptoms

- `Terracotta` through the old proxy is expected: the proxy answers/relays RakNet,
  while a 26.60 client no longer uses RakNet for the join.
- `Door` on a direct Tailnet connection means the NetherNet path is failing
  separately. The likely causes are unavailable signaling, unreachable ICE
  candidates, or a missing WebRTC UDP port.

## Server-side Checks

Run these on the updated BDS host without restarting the world:

1. Confirm the BDS version is 1.26.60 or newer and that startup logs say NetherNet
   is enabled.
2. Query the signaling endpoint locally:

   ```text
   curl -i http://127.0.0.1:19132/v1/join
   ```

   It must return HTTP 2xx, `application/json`, and server metadata including
   protocol/version. A 404, connection refusal, or RakNet-only listener confirms
   signaling is not available.
3. From the Windows Tailnet client, query the same endpoint through the Tailnet
   address and test the TCP port:

   ```powershell
   curl.exe -v http://<tailnet-ip>:<signaling-port>/v1/join
   Test-NetConnection <tailnet-ip> -Port <signaling-port>
   ```

4. Verify the WebRTC gameplay UDP port is also reachable through the Tailnet and
   host firewall. NetherNet needs TCP signaling plus UDP ICE/WebRTC traffic; the
   ports may be the same or separate depending on the BDS configuration.
5. Inspect the SDP answer/logs for an ICE candidate that contains the Tailnet
   address. A server advertising only a private LAN address will pass signaling
   but fail the WebRTC connectivity checks.
6. Preserve the NetherNet server identity key across restarts. Replacing it causes
   client trust-on-first-use changes and can present as a connection failure.

## v0.2 Implementation

The v0.2 code adds:

- `--protocol raknet|nethernet`, defaulting to `nethernet`;
- `--protocol-version` for the old RakNet MOTD override;
- `--remote-signal-url` for an explicit NetherNet upstream;
- a TCP signaling relay for `GET /v1/join` and
  `POST /v1/join/{networkID}`;
- a per-client encrypted UDP ICE relay that rewrites only candidate addresses.

NetherNet mode also requires `--media-client-address` (the address visible to
Bedrock clients) and `--media-upstream-address` (the address visible to the remote
server). `--media-bind` controls the local UDP relay socket; `:0` allocates a
port per client, while a fixed port is useful for a one-client lab test.

The relay preserves identity and DTLS fingerprints, rewrites the candidate
addresses to the proxy's client/upstream interfaces, and forwards encrypted UDP
packets without inspecting Bedrock payloads. ICE checks are inspected for routing.
The intended configuration does not require clients to have Tailnet access, but
real-client connectivity has not been verified. Restrict signaling to a trusted LAN;
it is unauthenticated and can be abused to send UDP checks to candidate addresses.

## Proxy Implication

Supporting current clients requires a NetherNet transport path, not a small
RakNet patch. The experimental HTTP relay does not implement LAN discovery or
LAN signaling, so it cannot yet deliver the console LAN-game workflow. In
addition to real-client testing, future work needs to:

- validate client identity assertions at the proxy boundary;
- support external STUN/TURN and IPv6 candidate mappings;
- bridge LAN discovery and trickle-ICE signaling to the HTTP endpoint;
- validate ICE routing and multihomed source addresses in the intended topology.

## LAN Bridge Status (2026-10-31 hardware test)

The experimental LAN bridge (`--lan-discover`) was validated on real clients up
to the upstream identity wall:

- Discovery advertisement works: a LAN client sees the bridged world and
  attempts to join (client and proxy coexist on UDP 7551; only hosts bind it).
- Offer translation works: the client's LAN offer (trickled candidates merged)
  reaches the upstream HTTP endpoint intact through the relay.
- **Blocked at upstream policy:** LAN clients do not attach an `a=identity`
  GameServerToken assertion to their SDP offers (LAN uses the nonce/auth-flag
  identity model instead). Mojang BDS rejects assertion-less offers with
  NetherNet error 37 (`IdentityNotAllowed`), observed in a packet capture as a
  2-byte `37` response body. The onboarding guide makes acceptance a server
  policy decision; no server.properties knob relaxes it, and the bridge cannot
  mint the player's assertion (it never holds player keys).

Consequence: LAN-discovery bridging via HTTP translation is blocked for Mojang
BDS upstreams. However, a LAN→LAN signaling tunnel (`--lan-upstream`) bypasses
the wall entirely: the proxy republishes the upstream's own LAN advertisement
and relays signaling verbatim, so the upstream experiences a vanilla LAN join
with no HTTP signaling and no SDP identity assertions. Validated on hardware
(2026-10-31): a LAN client discovered, joined, and played on the remote BDS
through the tunnel, with media flowing directly between the client and the
upstream's public ICE candidates. Tailnet-topology upstreams whose candidates
are not client-reachable still need answer-candidate rewriting plus a media
relay on the proxy. Clients that do their own HTTP signaling (manual server
entry on Win/mobile) also work through the relay. The Switch featured-server
DNS redirect path (`--dns-listen`, transport-independent) was subsequently
validated in production (2026-11-01): multiple Switch consoles join
through the DNS pin and HTTP relay, minting identity assertions on the HTTP
path with no operator intervention.

Candidate implementation references include `df-mc/go-nethernet` (Go, MIT) and
`PrismarineJS/node-nethernet` (Node, MIT). Both are active but NetherNet support
is still newer than the old RakNet stack.
