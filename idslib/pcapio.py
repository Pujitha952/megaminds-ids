"""Minimal classic-pcap writer and reader (Ethernet link type only).

Reads captures made by tcpdump / Wireshark. Wireshark saves pcapng by default, so convert first:
    editcap -F pcap in.pcapng out.pcap      (or: tshark -r in.pcapng -w out.pcap -F pcap)
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Tuple


@dataclass(slots=True)
class Packet:
    ts: float
    length: int
    eth_src: str = ""
    eth_dst: str = ""
    etype: int = 0
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    proto: int = 0          # 6 TCP, 17 UDP, 1 ICMP
    sport: int = 0
    dport: int = 0
    flags: int = 0
    arp_op: int = 0
    arp_sha: str = ""
    arp_spa: str = ""
    arp_tha: str = ""
    arp_tpa: str = ""


def write_pcap(path: str, packets: Iterable[Tuple[float, bytes]]) -> int:
    pkts = sorted(packets, key=lambda x: x[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in pkts:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)
    return len(pkts)


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_frame(ts: float, d: bytes) -> Optional[Packet]:
    if len(d) < 14:
        return None
    et = struct.unpack("!H", d[12:14])[0]
    off = 14
    if et == 0x8100 and len(d) >= 18:          # 802.1Q VLAN tag
        et = struct.unpack("!H", d[16:18])[0]
        off = 18
    p = Packet(ts=ts, length=len(d), eth_dst=_mac(d[0:6]), eth_src=_mac(d[6:12]), etype=et)
    if et == 0x0806 and len(d) >= off + 28:
        op, = struct.unpack("!H", d[off + 6:off + 8])
        p.arp_op = op
        p.arp_sha = _mac(d[off + 8:off + 14])
        p.arp_spa = socket.inet_ntoa(d[off + 14:off + 18])
        p.arp_tha = _mac(d[off + 18:off + 24])
        p.arp_tpa = socket.inet_ntoa(d[off + 24:off + 28])
        return p
    if et == 0x0800 and len(d) >= off + 20:
        ihl = (d[off] & 0x0F) * 4
        p.proto = d[off + 9]
        p.ip_src = socket.inet_ntoa(d[off + 12:off + 16])
        p.ip_dst = socket.inet_ntoa(d[off + 16:off + 20])
        t = off + ihl
        if p.proto == 6 and len(d) >= t + 14:
            p.sport, p.dport = struct.unpack("!HH", d[t:t + 4])
            p.flags = d[t + 13]
        elif p.proto == 17 and len(d) >= t + 8:
            p.sport, p.dport = struct.unpack("!HH", d[t:t + 4])
        return p
    return p  # other ethertypes (IPv6, ...) are kept but carry no L3 info


def read_pcap(path: str) -> List[Packet]:
    out: List[Packet] = []
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            raise ValueError("file too short to be a pcap")
        magic = head[:4]
        if magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError("pcapng detected - convert with: editcap -F pcap in.pcapng out.pcap")
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            e, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            e, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
        else:
            raise ValueError("not a pcap file")
        linktype = struct.unpack(e + "I", head[20:24])[0]
        if linktype != 1:
            raise ValueError(f"unsupported link type {linktype}; only Ethernet (1) is supported")
        div = 1e9 if nano else 1e6
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            sec, frac, caplen, _ = struct.unpack(e + "IIII", h)
            data = f.read(caplen)
            if len(data) < caplen:
                break
            p = parse_frame(sec + frac / div, data)
            if p is not None:
                out.append(p)
    return out
