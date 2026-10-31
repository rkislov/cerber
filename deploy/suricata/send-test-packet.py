#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One harmless ICMP echo in the isolated Cerber capture test namespace."""
import socket
import struct
import pathlib
import os

names = {name for _, name in socket.if_nameindex()}
if names != {"lo", "cerber-span", "cerber-tap"}:
    raise SystemExit("test sender requires the isolated Cerber network namespace")

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def mac(name):
    return bytes.fromhex(pathlib.Path("/sys/class/net", name, "address").read_text().strip().replace(":", ""))

payload = b"CERBER passive SPAN TAP verification " + os.urandom(8).hex().encode()
icmp = struct.pack("!BBHHH", 8, 0, 0, os.getpid() & 65535, 1) + payload
icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 7, 0, 64, 1, 0, socket.inet_aton("192.0.2.10"), socket.inet_aton("192.0.2.20"))
ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as connection:
    connection.bind(("cerber-tap", 0))
    connection.send(mac("cerber-span") + mac("cerber-tap") + b"\x08\x00" + ip + icmp)
print("Sent one isolated ICMP echo: 192.0.2.10 → 192.0.2.20")
