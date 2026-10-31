# Deploying bedrockproxy to a family LAN

The proxy must run on a device **on the same LAN** as the consoles (Raspberry Pi,
mini-PC, always-on box). It advertises a *remote* Bedrock server to every Bedrock
client on that LAN via the Friends / LAN tab.

## 1. Install the binary

Pick the matching build from `dist/` (or build on the box with Go ≥1.22):

| Box | Binary |
|-----|--------|
| Raspberry Pi 3/4/5 (64-bit) | `bedrockproxy-linux-arm64` |
| x86_64 Linux mini-PC | `bedrockproxy-linux-amd64` |
| Apple Silicon Mac | `bedrockproxy-darwin-arm64` |
| Intel Mac | `bedrockproxy-darwin-amd64` |
| Windows | `bedrockproxy-windows-amd64.exe` |

```sh
sudo install -m 0755 bedrockproxy-linux-arm64 /usr/local/bin/bedrockproxy
sudo mkdir -p /etc/bedrockproxy
sudo cp deploy/bedrockproxy.env /etc/bedrockproxy/bedrockproxy.env
sudoedit /etc/bedrockproxy/bedrockproxy.env   # set PROTOCOL, REMOTE, MOTD
```

## 2. Install the service

```sh
sudo cp deploy/bedrockproxy.service /etc/systemd/system/
sudo systemctl daemon-reload
# (create the unprivileged user the unit runs as)
sudo useradd -r -s /usr/sbin/nologin bedrockproxy || true
sudo systemctl enable --now bedrockproxy
sudo journalctl -u bedrockproxy -f
```

RakNet mode logs `bedrockproxy up: :19132 -> <REMOTE> ...`.
NetherNet mode logs `nethernet signaling relay up: :19132 -> <REMOTE> ...`.

## 3. Open the firewall (if any)

RakNet mode requires inbound UDP 19132 on the LAN interface:

```sh
sudo ufw allow in on eth0 to any port 19132 proto udp   # adjust iface name
```

NetherNet mode requires inbound TCP on the signaling bind and inbound UDP on the
media relay bind. Set `MEDIA_CLIENT_ADDRESS` to the proxy's LAN address and
`MEDIA_UPSTREAM_ADDRESS` to its Tailnet/public address. The proxy rewrites SDP
candidates and forwards encrypted UDP media between those interfaces.

## 4. Join

On any console / phone / Windows box on the same LAN, open Minecraft Bedrock →
the game appears under **Friends → LAN games**. Select it to join the remote
server.

## Troubleshooting

- **Legacy game doesn't appear:** RakNet mode must bind `:19132` (consoles scan that port).
  Check `--bind` and that nothing else holds 19132 (`sudo ss -lun | grep 19132`).
- **"Could not connect: Outdated client/server":** your console and the remote
  server run different Bedrock versions. Keep them on the same version; the proxy
  mirrors the remote's protocol automatically.
- **Switch specifically:** may not enumerate LAN games (see README roadmap). Use
  the DNS-hijack mode (planned) or fall back to a real Bedrock server on the LAN.
- **Verify what consoles will see:** `./bedping --addr 127.0.0.1:19132` from the
  box shows the advertised MOTD / protocol / version.
