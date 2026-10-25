"""Signature / threshold rule layer.

Each rule encodes the *defining behaviour* of an attack class. Thresholds are chosen from how
benign clients behave in this network (a client talks to a handful of ports, opens a few
connections per window, completes its handshakes) and are deliberately simple so an analyst can
read the reason for an alert.  Thresholds are per WINDOW seconds (default 5 s).
"""
from __future__ import annotations

import math
from typing import Dict, List, Optional

import pandas as pd

from .features import AUTH_PORTS, Capture

THRESHOLDS = {
    "port_scan_ports": 15,         # distinct dst ports on ONE target within a window
    "syn_flood_rate": 50.0,        # new connections / s to ONE (ip,port) ...
    "syn_flood_fail": 0.8,         # ... of which this fraction never completes the handshake
    "brute_force_conns": 8,        # connections to ONE auth service (SSH/FTP/RDP..) in a window
}


def _severity(ratio: float) -> str:
    return "Medium" if ratio < 2 else "High" if ratio < 5 else "Critical"


def _confidence(ratio: float) -> float:
    """Heuristic (NOT a calibrated probability): 0.6 at the threshold, rising with the margin."""
    return round(min(0.99, 0.6 + 0.1 * math.log2(max(ratio, 1.0))), 2)


def apply_rules(cap: Capture, th: Optional[Dict] = None,
                arp_bindings: Optional[Dict[str, str]] = None) -> List[dict]:
    th = {**THRESHOLDS, **(th or {})}
    W = cap.window
    alerts: List[dict] = []
    for r in cap.df.itertuples(index=False):
        base = {"window": r.window, "t_start": r.t_start, "src": r.src, "detector": "rule"}
        if r.max_ports_per_target >= th["port_scan_ports"]:
            ratio = r.max_ports_per_target / th["port_scan_ports"]
            alerts.append({**base, "category": "PORT_SCAN", "dst": r.scan_target,
                           "severity": _severity(ratio), "confidence": _confidence(ratio),
                           "why": (f"{r.max_ports_per_target} distinct destination ports probed on {r.scan_target} "
                                   f"in {W:g}s (rule: >= {th['port_scan_ports']}); "
                                   f"{r.fail_ratio:.0%} of connections failed or never completed"),
                           "evidence": {"ports_probed": int(r.max_ports_per_target), "new_conns": int(r.new_conns),
                                        "fail_ratio": round(r.fail_ratio, 2)}})
        rate = r.max_conns_per_target / W
        if rate >= th["syn_flood_rate"] and r.fail_ratio >= th["syn_flood_fail"]:
            ratio = rate / th["syn_flood_rate"]
            alerts.append({**base, "category": "SYN_FLOOD", "dst": r.top_target,
                           "severity": _severity(ratio), "confidence": _confidence(ratio),
                           "why": (f"{rate:.0f} connection attempts/s to {r.top_target} "
                                   f"(rule: >= {th['syn_flood_rate']:.0f}/s) with {r.fail_ratio:.0%} never completing "
                                   f"the TCP handshake (rule: >= {th['syn_flood_fail']:.0%})"),
                           "evidence": {"conns_per_s": round(rate, 1), "fail_ratio": round(r.fail_ratio, 2),
                                        "syn_rate": round(r.syn_rate, 1)}})
        if r.max_auth_conns >= th["brute_force_conns"]:
            ratio = r.max_auth_conns / th["brute_force_conns"]
            port = int(r.auth_target.rsplit(":", 1)[1])
            alerts.append({**base, "category": "BRUTE_FORCE", "dst": r.auth_target,
                           "severity": _severity(ratio), "confidence": _confidence(ratio),
                           "why": (f"{r.max_auth_conns} separate {AUTH_PORTS[port]} connections to {r.auth_target} "
                                   f"in {W:g}s (rule: >= {th['brute_force_conns']}) - repeated short "
                                   f"login attempts"),
                           "evidence": {"auth_conns": int(r.max_auth_conns), "service": AUTH_PORTS[port]}})
    alerts += _arp_rule(cap, arp_bindings)
    return alerts


def _arp_rule(cap: Capture, static: Optional[Dict[str, str]]) -> List[dict]:
    """IP->MAC binding table (learned from first sighting, or given statically); flag any change."""
    bindings = dict(static or {})
    seen: Dict[tuple, dict] = {}
    for e in sorted(cap.arp_events, key=lambda e: e["ts"]):
        ip, mac = e["claimed_ip"], e["mac"]
        known = bindings.get(ip)
        if known is None:
            bindings[ip] = mac
            continue
        if mac != known:
            k = (e["window"], e["src"], ip, mac)
            if k in seen:
                seen[k]["evidence"]["conflicting_replies"] += 1
                continue
            seen[k] = {"window": e["window"], "t_start": e["window"] * cap.window, "src": e["src"],
                       "detector": "rule", "category": "ARP_SPOOF", "dst": ip, "severity": "Critical",
                       "confidence": 0.95,
                       "why": (f"ARP reply from {mac} (host {e['src']}) claims {ip}, which was bound to {known}; "
                               f"an IP->MAC binding changed - classic ARP cache poisoning / man-in-the-middle"),
                       "evidence": {"claimed_ip": ip, "known_mac": known, "new_mac": mac, "conflicting_replies": 1}}
    return list(seen.values())
