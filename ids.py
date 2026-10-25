#!/usr/bin/env python3
"""Command-line interface for the hybrid network IDS.

  python ids.py train                          # fit + calibrate the anomaly model on benign pcaps
  python ids.py detect --pcap data/pcaps/s2_portscan.pcap
  python ids.py detect --pcap X.pcap --mode rules|ml|hybrid --json out.json --html report.html -v
  python ids.py list                           # list bundled pcaps
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

from idslib.detector import MODEL_PATH, MODES, detect, train
from idslib.report import write_html

PCAP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "pcaps")


def cmd_train(a):
    m = train(a.train_pcap, a.val_pcap, a.model, a.window, a.target_fpr)
    print(f"model saved to {a.model}  (anomaly threshold {m.threshold:.3f})")


def cmd_list(_):
    for p in sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap"))):
        print(os.path.relpath(p))


def cmd_detect(a):
    res = detect(a.pcap, a.mode, a.window, a.model,
                 arp_bindings=dict(x.split("=") for x in a.arp_binding) if a.arp_binding else None)
    cap = res.cap
    print(f"capture: {a.pcap}\n  {cap.n_packets} packets, {cap.t1 - cap.t0:.1f}s, "
          f"{len(cap.df)} source-windows ({a.window:g}s windows), mode={a.mode}")
    if not res.alerts:
        print("\nNo alerts - traffic looks normal.")
    else:
        print(f"\n{len(res.alerts)} alert(s):\n")
        print(f"{'#':>3} {'t(s)':>6}  {'source':<15} {'category':<12} {'sev':<8} {'conf':>4}  {'by':<8} target")
        for x in res.alerts:
            print(f"{x['id']:>3} {x['t_start']:>6.0f}  {x['src']:<15} {x['category']:<12} {x['severity']:<8} "
                  f"{x['confidence']:>4.2f}  {x['detector']:<8} {x.get('dst') or '-'}")
            if a.verbose:
                print(f"       why: {x['why']}")
        s = {}
        for x in res.alerts:
            s.setdefault((x["src"], x["category"]), []).append(x["t_start"])
        print("\nSummary by source/category:")
        for (src, cat), ts in s.items():
            print(f"  {src:<15} {cat:<12} {len(ts):>3} window(s), t={min(ts):.0f}s..{max(ts) + cap.window:.0f}s")
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res.alerts, f, indent=2, default=str)
        print(f"\nJSON written to {a.json}")
    if a.html:
        write_html(res, a.html, title=os.path.basename(a.pcap))
        print(f"HTML report written to {a.html}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Hybrid (rules + Isolation Forest) network IDS",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("train", help="train + calibrate anomaly model on benign traffic")
    t.add_argument("--train-pcap", default=os.path.join(PCAP_DIR, "train_benign.pcap"))
    t.add_argument("--val-pcap", default=os.path.join(PCAP_DIR, "val_benign.pcap"))
    t.add_argument("--model", default=MODEL_PATH)
    t.add_argument("--window", type=float, default=5.0)
    t.add_argument("--target-fpr", type=float, default=0.002)
    t.set_defaults(fn=cmd_train)
    d = sub.add_parser("detect", help="run detection on a pcap")
    d.add_argument("--pcap", required=True)
    d.add_argument("--mode", choices=MODES, default="hybrid")
    d.add_argument("--window", type=float, default=5.0)
    d.add_argument("--model", default=MODEL_PATH)
    d.add_argument("--arp-binding", nargs="*", metavar="IP=MAC", help="trusted static ARP bindings")
    d.add_argument("--json")
    d.add_argument("--html")
    d.add_argument("-v", "--verbose", action="store_true", help="print the reason for every alert")
    d.set_defaults(fn=cmd_detect)
    l = sub.add_parser("list", help="list bundled pcaps")
    l.set_defaults(fn=cmd_list)
    a = ap.parse_args(argv)
    try:
        a.fn(a)
    except (FileNotFoundError, ValueError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
