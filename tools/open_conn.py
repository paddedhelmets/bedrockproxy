#!/usr/bin/env python3
"""Send a RakNet ID_OPEN_CONNECTION_REQUEST_1 (0x07) and print any reply.

End-to-end relay test: send the first packet of the RakNet *connection*
handshake (not just discovery) to the proxy. If a reply (0x08 reply-1, or
anything) comes back, the round-trip client->proxy->remote->proxy->client works.
"""
import socket, sys

MAGIC = bytes([0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
               0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78])
ID_OPEN_CONN_REQ_1 = 0x07
RAKNET_PROTO_VER = 11  # current Bedrock RakNet protocol version

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 19130

# Packet body = ID + MAGIC + proto ver; pad with zeros so total len == desired MTU.
mtu = 1400
pkt = bytes([ID_OPEN_CONN_REQ_1]) + MAGIC + bytes([RAKNET_PROTO_VER]) + bytes(mtu - 18)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3.0)
s.sendto(pkt, (host, port))
print(f"sent OpenConnectionRequest1 ({len(pkt)}B) to {host}:{port}")
try:
    data, addr = s.recvfrom(4096)
    print(f"reply from {addr} ({len(data)}B) id=0x{data[0]:02x}")
    print(f"  hex head: {data[:48].hex()}")
    if data[0] == 0x08:
        print("  -> ID_OPEN_CONNECTION_REPLY_1 : RELAY WORKS (round-trip)")
except socket.timeout:
    print("no reply (timeout)")
