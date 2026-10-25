"""Raw packet builders (Ethernet / IPv4 / TCP / UDP / ICMP / ARP) with valid checksums.

Pure standard library so the project has no packet-crafting dependency. Frames built here
open cleanly in Wireshark / tcpdump.
"""
from __future__ import annotations

import socket
import struct

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def mac2b(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def ip2b(ip: str) -> bytes:
    return socket.inet_aton(ip)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ethernet(dst_mac: str, src_mac: str, ethertype: int, payload: bytes) -> bytes:
    return mac2b(dst_mac) + mac2b(src_mac) + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 0, ttl: int = 64) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF,
                      0x4000, ttl, proto, 0, ip2b(src), ip2b(dst))
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:] + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return ip2b(src) + ip2b(dst) + struct.pack("!BBH", 0, proto, length)


def tcp_segment(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
                flags: int, payload: bytes = b"", win: int = 64240) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      5 << 4, flags, win, 0, 0)
    c = checksum(_pseudo(src, dst, 6, len(hdr) + len(payload)) + hdr + payload)
    return hdr[:16] + struct.pack("!H", c) + hdr[18:] + payload


def udp_datagram(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    c = checksum(_pseudo(src, dst, 17, len(hdr) + len(payload)) + hdr + payload) or 0xFFFF
    return hdr[:6] + struct.pack("!H", c) + payload


def icmp_echo(icmp_type: int, ident: int, seq: int, payload: bytes = b"abcdefgh" * 4) -> bytes:
    hdr = struct.pack("!BBHHH", icmp_type, 0, 0, ident, seq)
    c = checksum(hdr + payload)
    return hdr[:2] + struct.pack("!H", c) + hdr[4:] + payload


def arp_packet(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op,
                       mac2b(sha), ip2b(spa), mac2b(tha), ip2b(tpa))
