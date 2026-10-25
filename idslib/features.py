"""Feature extraction: pcap -> per-(time window, source IP) behavioural features.

Why per-source, per-window?  Every attack in scope (scan, flood, brute force, ARP poisoning) is a
*behaviour of one host over a short period*, so we summarise what each source did in each
WINDOW-second slice.  Connection (flow) tracking gives us handshake outcome, which separates
a scan / flood (handshakes fail or never complete) from a legitimate surge (they complete).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

from .pcapio import Packet, read_pcap

SYN_F, ACK_F, RST_F = 0x02, 0x10, 0x04
AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC"}

# Features fed to the ML model (explained in docs / report)
ML_FEATURES = ["pps", "bytes_per_s", "avg_pkt_size", "unique_dst_ips", "new_conns", "fail_ratio",
               "max_ports_per_target", "max_conns_per_target", "arp_unsolicited"]


@dataclass(slots=True)
class Flow:
    src: str
    sport: int
    dst: str
    dport: int
    t_syn: float
    window: int
    t_synack: Optional[float] = None
    established: bool = False
    refused: bool = False       # RST from the target before establishment
    reset_by_init: bool = False
    syns: int = 1
    pkts: int = 1


@dataclass
class Capture:
    path: str
    window: float
    t0: float
    t1: float
    df: pd.DataFrame
    flows: List[Flow]
    arp_events: List[dict] = field(default_factory=list)
    mac_to_ip: Dict[str, str] = field(default_factory=dict)
    n_packets: int = 0


def extract(path_or_packets, window: float = 5.0) -> Capture:
    pkts: List[Packet] = read_pcap(path_or_packets) if isinstance(path_or_packets, str) else path_or_packets
    if not pkts:
        raise ValueError("capture contains no packets")
    pkts = sorted(pkts, key=lambda p: p.ts)
    t0, t1 = pkts[0].ts, pkts[-1].ts

    # MAC -> IP, only when unambiguous (a router/relay MAC carries many source IPs -> keep the MAC itself)
    macs: Dict[str, Set[str]] = defaultdict(set)
    for p in pkts:
        if p.ip_src:
            macs[p.eth_src].add(p.ip_src)
    mac_to_ip: Dict[str, str] = {m: next(iter(ips)) for m, ips in macs.items() if len(ips) == 1}

    st: Dict[Tuple[int, str], dict] = defaultdict(lambda: defaultdict(float))
    dsts: Dict[Tuple[int, str], Set[str]] = defaultdict(set)
    flows: Dict[Tuple[str, int, str, int], Flow] = {}
    pending_arp: Dict[Tuple[str, str], float] = {}
    arp_events: List[dict] = []

    for p in pkts:
        w = int((p.ts - t0) // window)
        if p.etype == 0x0806:                                  # ---- ARP
            # attribute by the real sender (Ethernet MAC), never by the (spoofable) claimed IP
            who = mac_to_ip.get(p.eth_src, p.eth_src)
            s = st[(w, who)]
            s["pkts"] += 1
            s["bytes"] += p.length
            if p.arp_op == 1:
                s["arp_req"] += 1
                pending_arp[(p.arp_spa, p.arp_tpa)] = p.ts
            elif p.arp_op == 2:
                s["arp_reply"] += 1
                req_t = pending_arp.get((p.arp_tpa, p.arp_spa))
                solicited = req_t is not None and p.ts - req_t <= 10.0
                if not solicited:
                    s["arp_unsolicited"] += 1
                arp_events.append({"ts": p.ts, "window": w, "src": who, "claimed_ip": p.arp_spa,
                                   "mac": p.arp_sha, "eth_src": p.eth_src, "solicited": solicited})
            continue
        if not p.ip_src:
            continue
        s = st[(w, p.ip_src)]
        s["pkts"] += 1
        s["bytes"] += p.length
        dsts[(w, p.ip_src)].add(p.ip_dst)
        if p.proto == 1:
            s["icmp"] += 1
        elif p.proto == 17:
            s["udp"] += 1
        elif p.proto == 6:
            f = p.flags
            fwd = (p.ip_src, p.sport, p.ip_dst, p.dport)
            rev = (p.ip_dst, p.dport, p.ip_src, p.sport)
            if (f & SYN_F) and not (f & ACK_F):
                if fwd in flows:
                    flows[fwd].syns += 1                       # retransmission
                else:
                    flows[fwd] = Flow(p.ip_src, p.sport, p.ip_dst, p.dport, p.ts, w)
                s["syn_out"] += 1
            elif (f & SYN_F) and (f & ACK_F):
                s["synack_out"] += 1
                fl = flows.get(rev)
                if fl is not None and fl.t_synack is None:
                    fl.t_synack = p.ts
            elif f & RST_F:
                if rev in flows and not flows[rev].established:
                    flows[rev].refused = True
                if fwd in flows:
                    flows[fwd].reset_by_init = True
            else:
                fl = flows.get(fwd)
                if fl is not None and fl.t_synack is not None and not fl.established:
                    fl.established = True
            fl = flows.get(fwd) or flows.get(rev)
            if fl is not None:
                fl.pkts += 1

    # ---- connection-level aggregation, attributed to the INITIATOR's window
    new_conns = defaultdict(int)
    failed = defaultdict(int)
    per_target_ports: Dict[Tuple[int, str], Dict[str, Set[int]]] = defaultdict(lambda: defaultdict(set))
    per_tp_count: Dict[Tuple[int, str], Dict[Tuple[str, int], int]] = defaultdict(lambda: defaultdict(int))
    for fl in flows.values():
        key = (fl.window, fl.src)
        new_conns[key] += 1
        if not fl.established:
            failed[key] += 1
        per_target_ports[key][fl.dst].add(fl.dport)
        per_tp_count[key][(fl.dst, fl.dport)] += 1

    rows = []
    for (w, src), s in st.items():
        key = (w, src)
        pk = s["pkts"]
        nc = new_conns.get(key, 0)
        ports = per_target_ports.get(key, {})
        tp = per_tp_count.get(key, {})
        scan_t, scan_n = (max(((d, len(v)) for d, v in ports.items()), key=lambda x: x[1]) if ports else ("", 0))
        top_t, top_n = (max(tp.items(), key=lambda x: x[1]) if tp else (("", 0), 0))
        auth = {k: v for k, v in tp.items() if k[1] in AUTH_PORTS}
        auth_t, auth_n = (max(auth.items(), key=lambda x: x[1]) if auth else (("", 0), 0))
        rows.append({
            "window": w, "t_start": w * window, "src": src,
            "pkts": pk, "bytes": s["bytes"],
            "pps": pk / window, "bytes_per_s": s["bytes"] / window,
            "avg_pkt_size": s["bytes"] / pk if pk else 0.0,
            "unique_dst_ips": len(dsts.get(key, ())),
            "new_conns": nc, "syn_rate": s["syn_out"] / window,
            "fail_ratio": failed.get(key, 0) / nc if nc else 0.0,
            "max_ports_per_target": scan_n, "scan_target": scan_t,
            "max_conns_per_target": top_n, "top_target": f"{top_t[0]}:{top_t[1]}" if top_n else "",
            "max_auth_conns": auth_n,
            "auth_target": f"{auth_t[0]}:{auth_t[1]}" if auth_n else "",
            "arp_reply": s["arp_reply"], "arp_unsolicited": s["arp_unsolicited"],
            "icmp": s["icmp"], "udp": s["udp"], "synack_out": s["synack_out"],
        })
    df = pd.DataFrame(rows).sort_values(["window", "src"]).reset_index(drop=True)
    return Capture(path=path_or_packets if isinstance(path_or_packets, str) else "<memory>",
                   window=window, t0=t0, t1=t1, df=df, flows=list(flows.values()),
                   arp_events=arp_events, mac_to_ip=mac_to_ip, n_packets=len(pkts))


def server_perf(cap: Capture, victim: str, dport: Optional[int] = None,
                exclude_srcs: Set[str] = frozenset()) -> pd.DataFrame:
    """Per-window service-health metrics for a target host (used to quantify DoS impact).

    Only flows from non-excluded (i.e. legitimate) sources feed the latency / success columns.
    """
    rows = []
    by_w: Dict[int, List[Flow]] = defaultdict(list)
    all_syn: Dict[int, int] = defaultdict(int)
    for fl in cap.flows:
        if fl.dst != victim or (dport and fl.dport != dport):
            continue
        all_syn[fl.window] += 1
        if fl.src not in exclude_srcs:
            by_w[fl.window].append(fl)
    for w in sorted(all_syn):
        legit = by_w.get(w, [])
        lat = [(f.t_synack - f.t_syn) * 1000 for f in legit if f.t_synack is not None]
        ok = [f for f in legit if f.established]
        rows.append({
            "window": w, "t_start": w * cap.window,
            "syn_in_per_s": all_syn[w] / cap.window,
            "legit_conns": len(legit),
            "legit_success_pct": 100.0 * len(ok) / len(legit) if legit else np.nan,
            "legit_median_handshake_ms": float(np.median(lat)) if lat else np.nan,
        })
    return pd.DataFrame(rows)
