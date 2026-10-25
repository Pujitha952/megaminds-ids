# AI-Driven Network Traffic Analysis and Intrusion Detection System

Megaminds IT Services - Cybersecurity & Network Security Research Intern, Round 1 take-home assessment.

A hybrid IDS that ingests a packet capture, turns it into per-host behavioural features, and flags
**port scans, SYN-flood DoS, SSH brute force and ARP spoofing** with an explanation for every alert.
It combines a transparent **rule layer** (known attack behaviours) with an **Isolation Forest** trained on
benign traffic only (to surface *unusual* behaviour that has no rule).

| Layer | Catches | Weakness (measured, see report) |
|---|---|---|
| Rules | scan, flood, brute force, ARP binding change - precisely, with reasons | blind to anything below its thresholds (low-and-slow scan) |
| Isolation Forest | "this host behaves unlike anything seen in benign traffic" | false alarms on legitimate surges; blind to a feature that never varied in training (ARP) |

## Quick start

```bash
git clone <your-repo-url> && cd <repo>
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python ids.py list                                        # bundled captures
python ids.py detect --pcap data/pcaps/s2_portscan.pcap -v
python ids.py detect --pcap data/pcaps/s3_dos.pcap --html results/s3.html   # analyst report with timeline
streamlit run dashboard.py                                # optional dashboard
```

Python 3.10+ (developed on 3.13). Only `numpy`, `pandas`, `scikit-learn`, `matplotlib`, `joblib` are
needed for the CLI; `streamlit` only for the dashboard. **No packet-crafting library is required** - the
pcap reader/writer and packet builders are in `idslib/` (stdlib only).

## Reproduce everything from scratch

```bash
python generate_traffic.py     # (re)creates data/pcaps/*.pcap + *.labels.json  (seeded -> byte-identical)
python ids.py train            # fits the Isolation Forest on train_benign, calibrates threshold on val_benign
python evaluate.py             # -> results/metrics.md, metrics.json, figures/*.png
python -m pytest -q            # 8 tests
```
(`make all` does the four steps.)

## Scenarios (Section 6 of the brief)

| # | Capture | Content | What to look for |
|---|---|---|---|
| 1 | `s1_normal.pcap` | benign only | zero alerts |
| 2 | `s2_portscan.pcap` | nmap-style SYN scan, 1000 ports @ ~100/s | `PORT_SCAN`, 466 ports in one 5 s window |
| 3 | `s3_dos.pcap` | SYN flood ~400/s for 30 s + legit clients suffering | `SYN_FLOOD`; legit handshake success drops to 13 % |
| 4a | `s4a_bruteforce.pcap` | hydra-style SSH guessing ~6/s | `BRUTE_FORCE` |
| 4b | `s4b_arpspoof.pcap` | gateway/victim ARP cache poisoning | `ARP_SPOOF` (binding change), attributed to attacker MAC |
| 5 | `s5_ambiguous.pcap` | **slow scan (missed)** + **benign flash crowd (false alarms)** | the honest failure cases |

Ground truth for each capture is in `data/pcaps/<name>.labels.json`.

## Repository layout

```
ids.py               CLI: train | detect | list
generate_traffic.py  seeded synthetic LAN traffic + attacks -> pcap + labels
evaluate.py          metrics, event-level detection, DoS impact, timeline figures
dashboard.py         Streamlit analyst UI
idslib/
  builders.py        Ethernet/IP/TCP/UDP/ICMP/ARP packet construction (valid checksums)
  pcapio.py          classic-pcap reader/writer
  features.py        flow tracking + per-(window, source) feature extraction
  rules.py           threshold / signature rules (+ ARP binding table)
  ml.py              Isolation Forest, calibration, per-alert feature explanations
  detector.py        hybrid merge policy
  report.py          timeline plot + HTML analyst report
data/pcaps/          generated captures and labels         models/   trained model
results/             metrics.md/json, figures, sample HTML reports
docs/                video script, viva preparation notes
REPORT.md            technical report
```

## Using your own capture

Classic `.pcap` with Ethernet link type only. Wireshark saves pcapng by default - convert first:
`editcap -F pcap in.pcapng out.pcap`. Thresholds in `idslib/rules.py` were set for a small LAN; tune
them for yours. For ARP spoofing, pass known-good bindings to avoid trusting "first seen":
`python ids.py detect --pcap x.pcap --arp-binding 192.168.10.1=02:00:00:00:00:01`.

## Ethics and scope

All traffic is synthetic or from the author's own lab. The attack generators only write packets to
files; nothing is sent on a network. Do not run scanners or floods against systems you do not own.

## AI-assistance disclosure (Section 12)

   I used an AI assistant (Claude) during development to help scaffold the code,
   generate the synthetic traffic scripts, and draft documentation. I reviewed the
   code, ran the full pipeline myself (traffic generation, training, evaluation,
   tests), and I can explain the traffic design, the features, the detection rules,
   the Isolation Forest layer, the results and the limitations. See docs/EXPLAIN_IT.md.
