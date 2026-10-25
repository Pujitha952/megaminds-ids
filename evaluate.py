#!/usr/bin/env python3
"""Evaluate rules / ML / hybrid on every labelled scenario.

Unit of evaluation: one (5-second window, source host) row.
  attack  = the row's source is the labelled attacker and the window overlaps the attack interval
  ignore  = the row's source is a labelled VICTIM during the attack (the server answering a flood
            legitimately looks "busy"; counting that as a false positive would be unfair, so it is
            excluded and reported separately as 'victim-side alerts')
  benign  = everything else (including flash-crowd clients)
Also reports event-level detection (was each attack found at all, how fast) and DoS service impact.
Outputs: results/metrics.json, results/metrics.md, results/figures/*.png
"""
from __future__ import annotations

import json
import os

import numpy as np
import pandas as pd

from idslib.detector import MODES, detect
from idslib.features import extract, server_perf
from idslib.report import timeline_png

PCAPS = "data/pcaps"
OUT = "results"
SCENARIOS = [("s1_normal", "S1 Normal baseline"), ("s2_portscan", "S2 Port scan"), ("s3_dos", "S3 SYN flood (DoS)"),
             ("s4a_bruteforce", "S4a SSH brute force"), ("s4b_arpspoof", "S4b ARP spoofing"),
             ("s5_ambiguous", "S5 Ambiguous (slow scan + flash crowd)")]
EXPECT = {"port_scan": "PORT_SCAN", "slow_scan": "PORT_SCAN", "syn_flood": "SYN_FLOOD",
          "ssh_bruteforce": "BRUTE_FORCE", "arp_spoof": "ARP_SPOOF"}


def label_rows(df, labels, W):
    y = np.array(["benign"] * len(df), dtype=object)
    for ev in labels["events"]:
        overlap = (df["t_start"] < ev["end"]) & (df["t_start"] + W > ev["start"])
        y[(df["src"] == ev["attacker"]) & overlap] = "attack"
        y[df["src"].isin(ev["victims"]) & overlap & (y != "attack")] = "ignore"
    return y


def confusion(y, flagged):
    keep = y != "ignore"
    yt, fl = (y[keep] == "attack"), flagged[keep]
    tp, fp = int((yt & fl).sum()), int((~yt & fl).sum())
    fn, tn = int((yt & ~fl).sum()), int((~yt & ~fl).sum())
    p = tp / (tp + fp) if tp + fp else float("nan")
    r = tp / (tp + fn) if tp + fn else float("nan")
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": p, "recall": r,
            "f1": 2 * p * r / (p + r) if tp else float("nan"), "accuracy": (tp + tn) / max(1, keep.sum())}


def pct(x):
    return "n/a" if x != x else f"{100 * x:.1f}%"


def main():
    os.makedirs(f"{OUT}/figures", exist_ok=True)
    per, agg_y, agg_flag, events_out, extra = {}, [], {m: [] for m in MODES}, [], {}
    keys = [k for k, _ in SCENARIOS]
    for key, title in SCENARIOS:
        labels = json.load(open(f"{PCAPS}/{key}.labels.json"))
        cap = extract(f"{PCAPS}/{key}.pcap")
        W = cap.window
        y = label_rows(cap.df, labels, W)
        agg_y.append(y)
        per[key] = {"title": title}
        for mode in MODES:
            res = detect(None, mode, cap=cap)
            flagged_keys = {(a["window"], a["src"]) for a in res.alerts}
            flagged = np.array([(w, s) in flagged_keys for w, s in zip(cap.df["window"], cap.df["src"])])
            agg_flag[mode].append(flagged)
            per[key][mode] = confusion(y, flagged)
            per[key][mode]["alerts"] = len(res.alerts)
            per[key][mode]["victim_side_alerts"] = int(((y == "ignore") & flagged).sum())
            for ev in labels["events"]:
                al = [a for a in res.alerts if a["src"] == ev["attacker"]
                      and a["t_start"] < ev["end"] and a["t_start"] + W > ev["start"]]
                typed = [a for a in al if a["category"] == EXPECT[ev["type"]]]
                first = min((a["t_start"] for a in al), default=None)
                events_out.append({"scenario": key, "mode": mode, "event": ev["type"], "detected": bool(al),
                                   "correctly_typed": bool(typed),
                                   "time_to_detect_s": None if first is None else round(max(0.0, first + W - ev["start"]), 1),
                                   "alert_windows": len(al)})
            if mode == "hybrid":
                timeline_png(res, f"{OUT}/figures/{key}_timeline.png", title=f"{title} - hybrid alerts")
                extra[key] = res
        if key == "s3_dos":
            ev = labels["events"][0]
            perf = server_perf(cap, "192.168.10.10", 80, exclude_srcs={ev["attacker"]})
            before = perf[perf.t_start + W <= ev["start"]]
            during = perf[(perf.t_start >= ev["start"]) & (perf.t_start + W <= ev["end"])]
            after = perf[perf.t_start >= ev["end"] + W]
            pk = cap.df.groupby("window")["pkts"].sum() / W
            tl = lambda lo, hi: float(pk[(pk.index * W >= lo) & ((pk.index + 1) * W <= hi)].mean())
            extra["dos_impact"] = {
                phase: {"server_inbound_syn_per_s": float(d["syn_in_per_s"].mean()),
                        "legit_handshake_success_pct": float(d["legit_success_pct"].mean()),
                        "legit_median_handshake_ms": float(d["legit_median_handshake_ms"].median())}
                for phase, d in (("before", before), ("during", during), ("after", after))}
            extra["dos_impact"]["before"]["total_pkts_per_s"] = tl(0, ev["start"])
            extra["dos_impact"]["during"]["total_pkts_per_s"] = tl(ev["start"], ev["end"])
            extra["dos_impact"]["after"]["total_pkts_per_s"] = tl(ev["end"] + W, 1e9)
            perf.to_csv(f"{OUT}/s3_server_perf.csv", index=False)
    y_all = np.concatenate(agg_y)
    overall = {m: confusion(y_all, np.concatenate(agg_flag[m])) for m in MODES}
    core = [i for i, k in enumerate(keys) if k != "s5_ambiguous"]          # S1-S4: designed-to-be-detectable
    y_core = np.concatenate([agg_y[i] for i in core])
    overall_core = {m: confusion(y_core, np.concatenate([agg_flag[m][i] for i in core])) for m in MODES}

    # ---------- write json + markdown
    dos = extra.pop("dos_impact")
    json.dump({"per_scenario": per, "overall": overall, "overall_s1_s4": overall_core, "events": events_out, "dos_impact": dos},
              open(f"{OUT}/metrics.json", "w"), indent=2)
    L = ["# Evaluation results\n", "Unit: (5 s window, source host). Victim-side rows during an attack are excluded "
         "(reported as 'victim-side alerts').\n"]
    for name, tab in (("Scenarios S1-S4 (attacks the detectors were designed for)", overall_core),
                      ("All six scenarios, including the S5 stress test", overall)):
        L += [f"## {name}\n", "| mode | TP | FP | FN | TN | precision | recall | F1 | accuracy |", "|---|---|---|---|---|---|---|---|---|"]
        for m in MODES:
            o = tab[m]
            L.append(f"| {m} | {o['TP']} | {o['FP']} | {o['FN']} | {o['TN']} | {pct(o['precision'])} | {pct(o['recall'])} | "
                     f"{pct(o['f1'])} | {pct(o['accuracy'])} |")
        L.append("")
    L += ["\n## Per scenario (hybrid unless stated)\n", "| scenario | mode | TP | FP | FN | TN | precision | recall | victim-side alerts |",
          "|---|---|---|---|---|---|---|---|---|"]
    for key, title in SCENARIOS:
        for m in MODES:
            o = per[key][m]
            L.append(f"| {title} | {m} | {o['TP']} | {o['FP']} | {o['FN']} | {o['TN']} | {pct(o['precision'])} | "
                     f"{pct(o['recall'])} | {o['victim_side_alerts']} |")
    L += ["\n## Event-level detection (was the attack found at all?)\n",
          "| scenario | event | mode | detected | correct type | time to detect (s) | alerted windows |", "|---|---|---|---|---|---|---|"]
    for e in events_out:
        L.append(f"| {e['scenario']} | {e['event']} | {e['mode']} | {'yes' if e['detected'] else '**NO**'} | "
                 f"{'yes' if e['correctly_typed'] else 'no'} | {e['time_to_detect_s'] if e['time_to_detect_s'] is not None else '-'} | "
                 f"{e['alert_windows']} |")
    L += ["\n## S3 - impact of the SYN flood on the web server (legitimate clients only)\n",
          "| phase | total pkts/s on LAN | SYN/s reaching server | legit handshake success | median SYN->SYN-ACK latency |",
          "|---|---|---|---|---|"]
    for ph in ("before", "during", "after"):
        d = dos[ph]
        L.append(f"| {ph} | {d['total_pkts_per_s']:.0f} | {d['server_inbound_syn_per_s']:.1f} | "
                 f"{d['legit_handshake_success_pct']:.0f}% | {d['legit_median_handshake_ms']:.1f} ms |")
    open(f"{OUT}/metrics.md", "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
