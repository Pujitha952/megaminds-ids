#!/usr/bin/env python3
"""Synthetic LAN traffic generator -> pcap files + ground-truth label files.

Why synthetic?  Real attacks may only be run against machines you own, and a self-contained,
seeded generator makes every result in this repository exactly reproducible
(`python generate_traffic.py`).  The packets are valid Ethernet/IP/TCP/UDP/ICMP/ARP frames,
so the pcaps open in Wireshark and can be replayed on a lab network (tcpreplay).

Topology (one /24 LAN):
    192.168.10.1    gateway
    192.168.10.10   web server (80/443)       <- victim of scan / flood
    192.168.10.20   ssh server (22)           <- victim of brute force
    192.168.10.53   DNS server
    192.168.10.101-112  benign clients
    192.168.10.200  attacker

Outputs (data/pcaps/): train_benign, val_benign, s1_normal, s2_portscan, s3_dos,
s4a_bruteforce, s4b_arpspoof, s5_ambiguous  (each with a .labels.json).
"""
from __future__ import annotations

import argparse
import json
import os

import numpy as np

from idslib.builders import (ACK, FIN, PSH, RST, SYN, arp_packet, ethernet, icmp_echo, ipv4,
                             tcp_segment, udp_datagram)
from idslib.pcapio import write_pcap

T0 = 1_760_000_000.0           # fixed epoch -> deterministic files
GATEWAY, WEB, SSH, DNS = "192.168.10.1", "192.168.10.10", "192.168.10.20", "192.168.10.53"
CLIENTS = [f"192.168.10.{i}" for i in range(101, 113)]
ATTACKER = "192.168.10.200"
SERVERS = [GATEWAY, WEB, SSH, DNS]


def mac_of(ip: str) -> str:
    return "02:00:00:00:00:%02x" % int(ip.split(".")[-1])


class Sim:
    """Collects (timestamp, frame) tuples."""

    def __init__(self, rng: np.random.Generator):
        self.pkts: list[tuple[float, bytes]] = []
        self.rng = rng
        self._id = 1

    def raw(self, ts, frame):
        self.pkts.append((T0 + ts, frame))

    def tcp(self, ts, s, d, sp, dp, seq, ack, flags, n=0):
        self._id += 1
        seg = tcp_segment(s, d, sp, dp, seq, ack, flags, b"x" * n)
        self.raw(ts, ethernet(mac_of(d), mac_of(s), 0x0800, ipv4(s, d, 6, seg, self._id)))

    def udp(self, ts, s, d, sp, dp, n):
        self._id += 1
        seg = udp_datagram(s, d, sp, dp, b"u" * n)
        self.raw(ts, ethernet(mac_of(d), mac_of(s), 0x0800, ipv4(s, d, 17, seg, self._id)))

    def icmp(self, ts, s, d, typ, seq):
        self._id += 1
        self.raw(ts, ethernet(mac_of(d), mac_of(s), 0x0800, ipv4(s, d, 1, icmp_echo(typ, 7, seq), self._id)))

    def arp(self, ts, op, sender_ip, target_ip, *, sender_mac=None, eth_src=None, target_mac=None,
            eth_dst=None):
        sm = sender_mac or mac_of(sender_ip)
        tm = target_mac or ("00:00:00:00:00:00" if op == 1 else mac_of(target_ip))
        es = eth_src or sm
        ed = eth_dst or ("ff:ff:ff:ff:ff:ff" if op == 1 else tm)
        self.raw(ts, ethernet(ed, es, 0x0806, arp_packet(op, sm, sender_ip, tm, target_ip)))

    # ------------------------------------------------------------------ TCP connection
    def tcp_conn(self, ts, c, sp, s, dp, *, outcome="ok", n_ex=2, rtt=0.001, think=0.01,
                 req=(150, 500), resp=(300, 1400)):
        r = self.rng
        cseq, sseq = int(r.integers(1, 2**31)), int(r.integers(1, 2**31))
        self.tcp(ts, c, s, sp, dp, cseq, 0, SYN)
        if outcome == "drop":                       # SYN retransmissions, no answer
            self.tcp(ts + 1.0, c, s, sp, dp, cseq, 0, SYN)
            self.tcp(ts + 3.0, c, s, sp, dp, cseq, 0, SYN)
            return ts + 3.0
        t = ts + rtt / 2
        if outcome == "refused":                    # closed port -> RST
            self.tcp(t, s, c, dp, sp, 0, cseq + 1, RST | ACK)
            return t
        self.tcp(t, s, c, dp, sp, sseq, cseq + 1, SYN | ACK)
        if outcome == "halfopen":                   # attacker never completes handshake
            return t
        t += rtt / 2
        if outcome == "reset_after_synack":         # nmap-style: RST after SYN-ACK
            self.tcp(t, c, s, sp, dp, cseq + 1, 0, RST)
            return t
        self.tcp(t, c, s, sp, dp, cseq + 1, sseq + 1, ACK)
        cseq += 1
        sseq += 1
        for _ in range(n_ex):
            t += float(r.exponential(think)) + 1e-4
            n = int(r.integers(*req))
            self.tcp(t, c, s, sp, dp, cseq, sseq, PSH | ACK, n)
            cseq += n
            t += rtt
            m = int(r.integers(*resp))
            self.tcp(t, s, c, dp, sp, sseq, cseq, PSH | ACK, m)
            sseq += m
            t += rtt
            self.tcp(t, c, s, sp, dp, cseq, sseq, ACK)
        t += rtt
        self.tcp(t, c, s, sp, dp, cseq, sseq, FIN | ACK)
        t += rtt
        self.tcp(t, s, c, dp, sp, sseq, cseq + 1, FIN | ACK)
        t += rtt
        self.tcp(t, c, s, sp, dp, cseq + 1, sseq + 1, ACK)
        return t


# ---------------------------------------------------------------------- benign traffic
def benign_traffic(sim: Sim, t_start: float, t_end: float, health=lambda t: (1.0, 1.0),
                   rate: float = 0.4):
    """Poisson sessions per client: web, DNS, occasional SSH, ping. ARP bootstrap + refresh."""
    r = sim.rng
    # ARP: first packet is at exactly t=0 (so capture start is deterministic)
    for i, c in enumerate(CLIENTS):
        for target in (GATEWAY, WEB):
            t = max(0.0, t_start) + 0.0 + 0.05 * i + (0.0 if target == GATEWAY else 0.01)
            sim.arp(t, 1, c, target)
            sim.arp(t + 0.0004, 2, target, c)
    for ip in (WEB, SSH, DNS):                       # servers resolve the gateway once
        sim.arp(t_start + 0.7, 1, ip, GATEWAY)
        sim.arp(t_start + 0.7004, 2, GATEWAY, ip)
    for c in CLIENTS:
        t = t_start + float(r.uniform(0, 2))
        next_arp = t_start + float(r.uniform(25, 55))
        while t < t_end:
            t += float(r.exponential(1 / rate))
            if t >= t_end:
                break
            u = r.random()
            sp = int(r.integers(32768, 61000))
            rtt = float(r.uniform(0.0004, 0.003))
            if u < 0.55:                                   # HTTP(S)
                p_ok, mult = health(t)
                port = 443 if r.random() < 0.5 else 80
                if r.random() > p_ok:
                    sim.tcp_conn(t, c, sp, WEB, port, outcome="drop")
                else:
                    sim.tcp_conn(t, c, sp, WEB, port, n_ex=int(r.integers(1, 6)), rtt=rtt * mult,
                                 think=0.02 * min(mult, 4))
            elif u < 0.85:                                 # DNS
                q = int(r.integers(55, 90))
                sim.udp(t, c, DNS, sp, 53, q)
                sim.udp(t + rtt, DNS, c, 53, sp, int(r.integers(90, 220)))
            elif u < 0.92:                                 # interactive SSH session
                sim.tcp_conn(t, c, sp, SSH, 22, n_ex=int(r.integers(8, 20)), rtt=rtt,
                             think=0.4, req=(40, 120), resp=(60, 300))
            else:                                          # ping
                tgt = GATEWAY if r.random() < 0.5 else WEB
                sim.icmp(t, c, tgt, 8, 1)
                sim.icmp(t + rtt, tgt, c, 0, 1)
            if t >= next_arp:                              # periodic ARP cache refresh
                sim.arp(t, 1, c, GATEWAY)
                sim.arp(t + 0.0004, 2, GATEWAY, c)
                next_arp = t + float(r.uniform(25, 55))


# ---------------------------------------------------------------------- attacks
def port_scan(sim, start, ports, per_sec, target=WEB, open_ports=(22, 80, 443), attacker=ATTACKER):
    """nmap -sS style: SYN to each port; closed -> RST/ACK, open -> SYN/ACK then RST."""
    r = sim.rng
    t = start
    for p in ports:
        t += float(r.exponential(1 / per_sec))
        sp = int(r.integers(40000, 60000))
        out = "reset_after_synack" if int(p) in open_ports else "refused"
        sim.tcp_conn(t, attacker, sp, target, int(p), outcome=out, rtt=0.0005)
    return t


def syn_flood(sim, start, end, pps, target=WEB, dport=80, attacker=ATTACKER, reply_prob=0.3):
    """hping3 --flood style: single source, random source ports, handshake never completed."""
    r = sim.rng
    t = start
    while True:
        t += float(r.exponential(1 / pps))
        if t >= end:
            break
        sp = int(r.integers(1024, 65535))
        seq = int(r.integers(1, 2**31))
        sim.tcp(t, attacker, target, sp, dport, seq, 0, SYN)
        if r.random() < reply_prob:                        # backlog nearly full: most SYNs unanswered
            sim.tcp(t + 0.0003, target, attacker, dport, sp, int(r.integers(1, 2**31)), seq + 1, SYN | ACK)


def ssh_bruteforce(sim, start, end, attempts_per_sec, target=SSH, attacker=ATTACKER):
    """hydra style: many short SSH connections, each ends after a failed login."""
    r = sim.rng
    t = start
    while True:
        t += float(r.exponential(1 / attempts_per_sec))
        if t >= end:
            break
        sim.tcp_conn(t, attacker, int(r.integers(40000, 60000)), target, 22, n_ex=5,
                     rtt=0.0008, think=0.01, req=(40, 120), resp=(40, 200))


def arp_spoof(sim, start, end, victim, gateway=GATEWAY, attacker=ATTACKER, interval=1.0):
    """Poison victim (gateway -> attacker MAC) and gateway (victim -> attacker MAC), like arpspoof/ettercap."""
    r = sim.rng
    am = mac_of(attacker)
    t = start
    while t < end:
        sim.arp(t, 2, gateway, victim, sender_mac=am, eth_src=am, target_mac=mac_of(victim))
        sim.arp(t + 0.002, 2, victim, gateway, sender_mac=am, eth_src=am, target_mac=mac_of(gateway))
        t += interval + float(r.uniform(-0.1, 0.1))


def flash_crowd(sim, start, dur, conns_per_client):
    """Legitimate surge: many clients each open many *successful* HTTP connections."""
    r = sim.rng
    for c in CLIENTS:
        for _ in range(conns_per_client):
            t = start + float(r.uniform(0, dur))
            sim.tcp_conn(t, c, int(r.integers(32768, 61000)), WEB, 80, n_ex=2,
                         rtt=float(r.uniform(0.0006, 0.004)), req=(100, 300), resp=(200, 900))


# ---------------------------------------------------------------------- scenarios
def build(name: str, seed: int):
    rng = np.random.default_rng(seed)
    sim = Sim(rng)
    labels = {"scenario": name, "events": [], "benign_events": []}

    def event(type_, start, end, attacker=ATTACKER, victims=(), note="", expected=True):
        labels["events"].append({"type": type_, "attacker": attacker, "start": start, "end": end,
                                 "victims": list(victims), "note": note, "expected_detectable": expected})

    if name in ("train_benign", "val_benign"):
        dur = 300.0
        benign_traffic(sim, 0, dur)
    elif name == "s1_normal":
        dur = 120.0
        benign_traffic(sim, 0, dur)
    elif name == "s2_portscan":
        dur = 120.0
        benign_traffic(sim, 0, dur)
        ports = rng.permutation(np.arange(1, 1025))[:1000]
        end = port_scan(sim, 30.0, ports, per_sec=100)
        event("port_scan", 30.0, end, victims=[WEB], note="nmap -sS style, 1000 ports @ ~100/s")
    elif name == "s3_dos":
        dur = 120.0
        a, b = 40.0, 70.0
        benign_traffic(sim, 0, dur, health=lambda t: (0.25, 40.0) if a <= t < b else (1.0, 1.0))
        syn_flood(sim, a, b, pps=400)
        event("syn_flood", a, b, victims=[WEB], note="hping3 --flood style, ~400 SYN/s to :80")
    elif name == "s4a_bruteforce":
        dur = 120.0
        benign_traffic(sim, 0, dur)
        ssh_bruteforce(sim, 30.0, 80.0, attempts_per_sec=6)
        event("ssh_bruteforce", 30.0, 80.0, victims=[SSH], note="hydra style, ~6 attempts/s")
    elif name == "s4b_arpspoof":
        dur = 120.0
        benign_traffic(sim, 0, dur)
        sim.arp(1.0, 1, ATTACKER, GATEWAY)               # attacker is an ordinary-looking LAN host too:
        sim.arp(1.0004, 2, GATEWAY, ATTACKER)
        for k in range(1, 12):                           # it pings the gateway now and then
            sim.icmp(k * 10.0, ATTACKER, GATEWAY, 8, k)
            sim.icmp(k * 10.0 + 0.001, GATEWAY, ATTACKER, 0, k)
        arp_spoof(sim, 40.0, 80.0, victim=CLIENTS[0])
        event("arp_spoof", 40.0, 80.0, victims=[CLIENTS[0], GATEWAY],
              note="gratuitous ARP replies poisoning victim + gateway, 1 Hz")
    elif name == "s5_ambiguous":
        dur = 120.0
        benign_traffic(sim, 0, dur)
        # (a) low-and-slow scan: one SYN every ~3 s -> stays under any per-window threshold
        t, ports = 10.0, rng.permutation(np.arange(1, 1025))[:40]
        for p in ports:
            t += float(rng.uniform(2.0, 4.0))
            sim.tcp_conn(t, ATTACKER, int(rng.integers(40000, 60000)), WEB, int(p),
                         outcome="reset_after_synack" if int(p) in (22, 80, 443) else "refused", rtt=0.0005)
        event("slow_scan", 10.0, t, victims=[WEB], expected=False,
              note="1 port every ~3 s: evades per-window thresholds")
        # (b) benign flash crowd: looks like a flood by volume
        flash_crowd(sim, 60.0, 6.0, conns_per_client=25)
        labels["benign_events"].append({"type": "flash_crowd", "start": 60.0, "end": 66.0,
                                        "note": "12 legit clients x 25 successful HTTP connections in 6 s"})
    else:
        raise ValueError(name)
    labels["duration"] = dur
    labels["seed"] = seed
    labels["attacker"] = ATTACKER
    return sim, labels


SCENARIOS = {"train_benign": 1, "val_benign": 3, "s1_normal": 2, "s2_portscan": 12, "s3_dos": 13,
             "s4a_bruteforce": 14, "s4b_arpspoof": 15, "s5_ambiguous": 16}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="data/pcaps")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    for name, seed in SCENARIOS.items():
        sim, labels = build(name, seed)
        n = write_pcap(os.path.join(args.out, f"{name}.pcap"), sim.pkts)
        with open(os.path.join(args.out, f"{name}.labels.json"), "w") as f:
            json.dump(labels, f, indent=2)
        print(f"{name:16s} {n:7d} packets  seed={seed}")


if __name__ == "__main__":
    main()
