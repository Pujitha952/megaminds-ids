# 8-10 minute video: script and shot list

Record your screen + voice (OBS, Zoom or Loom). Speak in your own words - this is a guide, not a teleprompter.
Upload as unlisted YouTube / Google Drive link, or as a file if allowed, and put the link in the README.

**Before recording:** `python generate_traffic.py && python ids.py train && python evaluate.py`; open a terminal
at the repo root, `results/figures/*.png`, and `REPORT.md` in tabs. Increase terminal font size.

| Time | Section | Show on screen | Say (key points) |
|---|---|---|---|
| 0:00-0:45 | Problem | title slide or README top | Signature IDS misses novel behaviour; behavioural/ML detection helps; I built a hybrid IDS that explains every alert. Four attack classes: scan, DoS, brute force, ARP spoofing. |
| 0:45-2:00 | Architecture | README "layout" or a simple box diagram | pcap -> flow tracker + 5 s window features -> rule layer + Isolation Forest -> hybrid merge -> alerts. Why hybrid: rules are precise but only know what I wrote; ML flags the unusual but can't name it. |
| 2:00-3:00 | Traffic / environment | `generate_traffic.py` header, `ls data/pcaps`, open one pcap in Wireshark | Synthetic seeded LAN (gateway, servers, 12 clients, attacker), real pcap frames, ground-truth labels. Why: only attack systems you own, reproducible. State the caveat: self-generated => optimistic. |
| 3:00-4:15 | Features | `idslib/features.py` feature table in REPORT | Per (window, source). Show 3 features and what attack each separates: `max_ports_per_target` (scan), `max_conns_per_target`+`fail_ratio` (flood vs flash crowd), ARP binding table. |
| 4:15-4:45 | Scenario 1 | `python ids.py detect --pcap data/pcaps/s1_normal.pcap` | No alerts. |
| 4:45-5:30 | Scenario 2 | `... s2_portscan.pcap -v` + timeline PNG | PORT_SCAN, 466 ports in 5 s, read the "why". Mention victim shows a Low ML anomaly (collateral, excluded in eval). |
| 5:30-6:30 | Scenario 3 | `... s3_dos.pcap -v`, then DoS impact table from `results/metrics.md` | SYN_FLOOD ~400/s, 100 % unfinished. Impact: legit handshake success 100 % -> 13 %, latency 0.9 ms -> 40 ms, recovers after. |
| 6:30-7:15 | Scenario 4 | `... s4a_bruteforce.pcap -v` and `... s4b_arpspoof.pcap -v` | Brute force via repeated SSH connections. ARP: IP->MAC binding changed; attributed to attacker's MAC, not the spoofed IP. Show rules vs `--mode ml` (ML misses ARP) -> why hybrid. |
| 7:15-8:15 | Scenario 5 | `... s5_ambiguous.pcap -v`, timeline figure | **Two failure cases.** Slow scan: 0 alerts, all 23 windows missed - below thresholds. Flash crowd: 17 low-severity ML anomalies on benign clients - volume != malice; rules stayed silent because handshakes completed. |
| 8:15-9:15 | Evaluation | `results/metrics.md` | S1-S4 hybrid: precision 96 %, recall 100 %, 1 FP. With S5: recall 54 %. Say plainly that the data is self-generated so numbers are optimistic. |
| 9:15-10:00 | Limitations / conclusion | REPORT section 9-10 | Evasion (slow, distributed, spoofed floods), single-subnet data, windows add latency. Next: CICIDS2017/live lab validation, multi-timescale features. Quick dashboard glimpse if time (`streamlit run dashboard.py`). |

Tips: do one take per scenario and cut; show the *explanation text* of an alert in every scenario - that is
a core requirement; do not just read code - the brief says a code-only walkthrough is insufficient.
