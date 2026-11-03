# Deploying bedrockproxy to a home LAN

The proxy must run on a device **on the same LAN** as the consoles (Raspberry Pi,
mini-PC, always-on box) for RakNet LAN discovery. NetherNet mode is a signaling
and media relay, not a LAN advertisement service.

## 1. Install the binary

Pick the matching build from `dist/` (or build on the box with Go 1.25+):

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
sudoedit /etc/bedrockproxy/bedrockproxy.env   # set PROTOCOL and upstream; see mode-specific settings
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

When upgrading an existing installation, install the updated unit and run
`systemctl daemon-reload`. If the existing environment file lacks `PROTOCOL`,
the unit selects RakNet to preserve service. The new example explicitly selects
NetherNet; do not overwrite an existing environment without reviewing it. For
NetherNet, configure a compatible signaling endpoint and both media addresses.

## 3. Open the firewall (if any)

RakNet mode requires inbound UDP 19132 on the LAN interface:

```sh
sudo ufw allow in on eth0 to any port 19132 proto udp   # adjust iface name
```

NetherNet mode requires inbound TCP on the signaling bind and inbound UDP on the
media relay's dynamically allocated UDP ports on both relevant network paths.
Set `MEDIA_CLIENT_ADDRESS` and `MEDIA_UPSTREAM_ADDRESS` to reachable proxy IPv4
addresses on the respective sides. Each session needs a separate UDP port;
fixed `MEDIA_BIND` ports prevent concurrent sessions, and port ranges are not
supported. NAT/firewall configuration and interoperability must be validated.

## 4. Join

In RakNet mode, look for the game under **Friends → LAN games** on supported
clients. Switch uses the separate RakNet DNS redirect instead. Real-console
validation remains pending. NetherNet requires a client that can reach the
signaling relay and does not itself create a LAN listing.

## Troubleshooting

- **Legacy game doesn't appear:** RakNet mode must bind `:19132` (consoles scan that port).
  Check `--bind` and that nothing else holds 19132 (`sudo ss -lun | grep 19132`).
- **"Could not connect: Outdated client/server":** your console and the remote
  server run different Bedrock versions. Keep them on the same version; the proxy
  mirrors the remote's protocol automatically.
- **Switch specifically:** use RakNet DNS mode as described in the main README;
  real-console validation is pending.
- **Verify what consoles will see:** `./bedping --addr 127.0.0.1:19132` from the
  box shows the advertised MOTD / protocol / version.
