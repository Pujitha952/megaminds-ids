import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np  # noqa: E402

from generate_traffic import ATTACKER, GATEWAY, WEB, Sim, build  # noqa: E402
from idslib.detector import detect  # noqa: E402
from idslib.features import extract  # noqa: E402
from idslib.pcapio import read_pcap, write_pcap  # noqa: E402

PC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "pcaps")


def test_pcap_roundtrip(tmp_path):
    sim = Sim(np.random.default_rng(0))
    sim.tcp_conn(0.0, "192.168.10.101", 40000, WEB, 80)
    sim.arp(1.0, 1, "192.168.10.101", GATEWAY)
    p = str(tmp_path / "a.pcap")
    n = write_pcap(p, sim.pkts)
    pk = read_pcap(p)
    assert len(pk) == n
    assert pk[0].flags == 0x02 and pk[0].dport == 80 and pk[0].ip_dst == WEB      # SYN first
    assert pk[-1].arp_op == 1 and pk[-1].arp_tpa == GATEWAY


def test_handshake_flow_states():
    sim = Sim(np.random.default_rng(0))
    sim.tcp_conn(0.0, "192.168.10.101", 40000, WEB, 80, outcome="ok")
    sim.tcp_conn(0.1, ATTACKER, 40001, WEB, 81, outcome="refused")
    sim.tcp_conn(0.2, ATTACKER, 40002, WEB, 80, outcome="halfopen")
    sim.tcp_conn(0.3, ATTACKER, 40003, WEB, 443, outcome="reset_after_synack")
    cap = extract([__import__("idslib.pcapio", fromlist=["x"]).parse_frame(t, f) for t, f in sim.pkts])
    est = {(f.sport): f.established for f in cap.flows}
    assert est == {40000: True, 40001: False, 40002: False, 40003: False}


def test_rules_on_scenarios():
    for name, cat in [("s2_portscan", "PORT_SCAN"), ("s3_dos", "SYN_FLOOD"),
                      ("s4a_bruteforce", "BRUTE_FORCE"), ("s4b_arpspoof", "ARP_SPOOF")]:
        res = detect(f"{PC}/{name}.pcap", "rules")
        cats = {a["category"] for a in res.alerts if a["src"] == ATTACKER}
        assert cat in cats, name
        assert all(a["why"] for a in res.alerts)             # every alert is explained


def test_benign_baseline_has_no_rule_alerts():
    assert detect(f"{PC}/s1_normal.pcap", "rules").alerts == []


def test_hybrid_baseline_quiet():
    assert detect(f"{PC}/s1_normal.pcap", "hybrid").alerts == []


def test_slow_scan_is_missed_by_design():
    res = detect(f"{PC}/s5_ambiguous.pcap", "hybrid")
    assert not [a for a in res.alerts if a["src"] == ATTACKER]


def test_arp_binding_conflict_attributed_to_attacker_not_claimed_ip():
    res = detect(f"{PC}/s4b_arpspoof.pcap", "rules")
    arp = [a for a in res.alerts if a["category"] == "ARP_SPOOF"]
    assert arp and all(a["src"] == ATTACKER and a["dst"] == GATEWAY for a in arp)


def test_generator_is_deterministic():
    a, _ = build("s2_portscan", 12)
    b, _ = build("s2_portscan", 12)
    assert a.pkts == b.pkts
