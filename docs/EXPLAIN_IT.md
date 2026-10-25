# Be able to explain this (Section 12 of the brief)

The brief says you may be asked to defend your data, features, detection logic, results and limitations.
Read the code once end to end (it is ~900 lines) and make sure you can answer these in your own words.

**Data**
- Why synthetic? Safe/legal, reproducible, labelled. What is the downside? Self-generated -> optimistic; simpler than real networks.
- What makes the packets "real"? Valid headers/checksums; they open in Wireshark; the reader also handles real pcaps.

**Features**
- Why per (window, source)? Attacks are behaviours of one host over a short time.
- Why `max_ports_per_target` instead of total unique ports? A busy client talking to many hosts shouldn't look like a scanner.
- Why does `fail_ratio` matter? It separates a flood/scan (handshakes fail) from a flash crowd (they succeed).
- Why attribute ARP to the Ethernet sender, not the claimed IP? The attacker forges the claimed IP.

**Detection**
- What does each rule check and why those thresholds? (`idslib/rules.py`; chosen from benign behaviour, not tuned on test pcaps.)
- Why Isolation Forest, trained on benign only? Unsupervised (no attack labels needed), flags "unlike normal".
- How was the ML threshold set? 99.8th percentile of scores on a separate benign validation capture.
- Why can the ML layer not see ARP spoofing? `arp_unsolicited` is constant 0 in training -> trees cannot split on it.
- What is "confidence"? A heuristic, not a probability. Say so.
- What does hybrid do when only ML fires? Reports `ANOMALY`, severity capped at Medium, lists top deviating features.

**Results**
- Why is recall 100 % in S1-S4 but 54 % overall? The slow scan (S5) is missed in every mode - by design.
- Why 17 false alarms in S5? Flash crowd: unusual volume, but benign. Rules didn't fire because handshakes completed.
- Why are victim servers excluded from scoring? A server answering a flood legitimately looks busy; counted separately.
- Is the DoS "impact" measured or simulated? The degradation is *modelled* in the generator, then *measured* from the pcap.

**Limitations / what next**
- Evasion: slow/distributed scans, spoofed-source floods, mimicry, training-set poisoning.
- Inline deployment: latency, fail-open vs fail-closed, false positives that block users.
- Next steps: CICIDS2017 + live lab, multi-timescale features, per-destination SYN imbalance.

**Good habit before submitting:** run `python ids.py detect --pcap data/pcaps/s2_portscan.pcap -v`,
change one threshold in `idslib/rules.py`, re-run, and see what changes. If you can predict it, you understand it.
