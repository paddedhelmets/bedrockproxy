#!/usr/bin/env python3
"""Send a RakNet ID_UNCONNECTED_PING to a Bedrock server and dump the pong.

Diagnostic tool: gives ground-truth MOTD/protocol/version strings the proxy
should mirror so clients never reject the advertised server as "outdated".
"""
import socket, struct, sys, time

MAGIC = bytes([0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
               0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78])
ID_PING = 0x01
ID_PONG = 0x1c


def ping(host, port, timeout=2.0, retries=8):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    for _ in range(retries):
        t = int(time.time() * 1000) & ((1 << 63) - 1)
        pkt = bytes([ID_PING]) + struct.pack(">q", t) + MAGIC + struct.pack(">q", 0x1337)
        s.sendto(pkt, (host, port))
        try:
            data, addr = s.recvfrom(4096)
            return data, addr
        except socket.timeout:
            continue
    return None, None


def parse_pong(data):
    if not data or data[0] != ID_PONG:
        return None
    ping_time = struct.unpack(">q", data[1:9])[0]
    server_id = struct.unpack(">q", data[9:17])[0]
    magic = data[17:33]
    (motd_len,) = struct.unpack(">H", data[33:35])
    motd = data[35:35 + motd_len].decode("utf-8", "replace")
    return dict(ping_time=ping_time, server_id=server_id, magic_ok=(magic == MAGIC),
                motd_len=motd_len, motd=motd, fields=motd.split(";"))


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 19132
    data, addr = ping(host, port)
    if not data:
        print(f"no response from {host}:{port}")
        sys.exit(1)
    print(f"reply from {addr}  ({len(data)} bytes)")
    print(f"raw hex: {data.hex()}")
    p = parse_pong(data)
    if not p:
        print(f"first byte = 0x{data[0]:02x} (expected 0x{ID_PONG:02x})")
        sys.exit(2)
    print(f"magic OK : {p['magic_ok']}")
    print(f"serverId : {p['server_id']}")
    print(f"MOTD len : {p['motd_len']}")
    print(f"MOTD     : {p['motd']}")
    names = ["edition", "motd1", "protocolVer", "versionName", "players",
             "maxPlayers", "serverId", "motd2", "gameType", "nintendoLimited",
             "ipv4Port", "ipv6Port", "(extra...)"]
    print("--- parsed fields ---")
    for i, f in enumerate(p["fields"]):
        label = names[i] if i < len(names) else f"field{i}"
        print(f"  {i:2d} {label:14} = {f!r}")


if __name__ == "__main__":
    main()
