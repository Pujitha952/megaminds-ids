# Evaluation results

Unit: (5 s window, source host). Victim-side rows during an attack are excluded (reported as 'victim-side alerts').

## Scenarios S1-S4 (attacks the detectors were designed for)

| mode | TP | FP | FN | TN | precision | recall | F1 | accuracy |
|---|---|---|---|---|---|---|---|---|
| rules | 27 | 0 | 0 | 1750 | 100.0% | 100.0% | 100.0% | 100.0% |
| ml | 18 | 1 | 9 | 1749 | 94.7% | 66.7% | 78.3% | 99.4% |
| hybrid | 27 | 1 | 0 | 1749 | 96.4% | 100.0% | 98.2% | 99.9% |

## All six scenarios, including the S5 stress test

| mode | TP | FP | FN | TN | precision | recall | F1 | accuracy |
|---|---|---|---|---|---|---|---|---|
| rules | 27 | 0 | 23 | 2087 | 100.0% | 54.0% | 70.1% | 98.9% |
| ml | 18 | 18 | 32 | 2069 | 50.0% | 36.0% | 41.9% | 97.7% |
| hybrid | 27 | 18 | 23 | 2069 | 60.0% | 54.0% | 56.8% | 98.1% |


## Per scenario (hybrid unless stated)

| scenario | mode | TP | FP | FN | TN | precision | recall | victim-side alerts |
|---|---|---|---|---|---|---|---|---|
| S1 Normal baseline | rules | 0 | 0 | 0 | 347 | n/a | n/a | 0 |
| S1 Normal baseline | ml | 0 | 0 | 0 | 347 | n/a | n/a | 0 |
| S1 Normal baseline | hybrid | 0 | 0 | 0 | 347 | n/a | n/a | 0 |
| S2 Port scan | rules | 3 | 0 | 0 | 347 | 100.0% | 100.0% | 0 |
| S2 Port scan | ml | 2 | 0 | 1 | 347 | 100.0% | 66.7% | 2 |
| S2 Port scan | hybrid | 3 | 0 | 0 | 347 | 100.0% | 100.0% | 2 |
| S3 SYN flood (DoS) | rules | 6 | 0 | 0 | 354 | 100.0% | 100.0% | 0 |
| S3 SYN flood (DoS) | ml | 6 | 1 | 0 | 353 | 85.7% | 100.0% | 0 |
| S3 SYN flood (DoS) | hybrid | 6 | 1 | 0 | 353 | 85.7% | 100.0% | 0 |
| S4a SSH brute force | rules | 10 | 0 | 0 | 352 | 100.0% | 100.0% | 0 |
| S4a SSH brute force | ml | 10 | 0 | 0 | 352 | 100.0% | 100.0% | 0 |
| S4a SSH brute force | hybrid | 10 | 0 | 0 | 352 | 100.0% | 100.0% | 0 |
| S4b ARP spoofing | rules | 8 | 0 | 0 | 350 | 100.0% | 100.0% | 0 |
| S4b ARP spoofing | ml | 0 | 0 | 8 | 350 | n/a | 0.0% | 0 |
| S4b ARP spoofing | hybrid | 8 | 0 | 0 | 350 | 100.0% | 100.0% | 0 |
| S5 Ambiguous (slow scan + flash crowd) | rules | 0 | 0 | 23 | 337 | n/a | 0.0% | 0 |
| S5 Ambiguous (slow scan + flash crowd) | ml | 0 | 17 | 23 | 320 | 0.0% | 0.0% | 2 |
| S5 Ambiguous (slow scan + flash crowd) | hybrid | 0 | 17 | 23 | 320 | 0.0% | 0.0% | 2 |

## Event-level detection (was the attack found at all?)

| scenario | event | mode | detected | correct type | time to detect (s) | alerted windows |
|---|---|---|---|---|---|---|
| s2_portscan | port_scan | rules | yes | yes | 5.0 | 3 |
| s2_portscan | port_scan | ml | yes | no | 5.0 | 2 |
| s2_portscan | port_scan | hybrid | yes | yes | 5.0 | 3 |
| s3_dos | syn_flood | rules | yes | yes | 5.0 | 6 |
| s3_dos | syn_flood | ml | yes | no | 5.0 | 6 |
| s3_dos | syn_flood | hybrid | yes | yes | 5.0 | 6 |
| s4a_bruteforce | ssh_bruteforce | rules | yes | yes | 5.0 | 10 |
| s4a_bruteforce | ssh_bruteforce | ml | yes | no | 5.0 | 10 |
| s4a_bruteforce | ssh_bruteforce | hybrid | yes | yes | 5.0 | 10 |
| s4b_arpspoof | arp_spoof | rules | yes | yes | 5.0 | 8 |
| s4b_arpspoof | arp_spoof | ml | **NO** | no | - | 0 |
| s4b_arpspoof | arp_spoof | hybrid | yes | yes | 5.0 | 8 |
| s5_ambiguous | slow_scan | rules | **NO** | no | - | 0 |
| s5_ambiguous | slow_scan | ml | **NO** | no | - | 0 |
| s5_ambiguous | slow_scan | hybrid | **NO** | no | - | 0 |

## S3 - impact of the SYN flood on the web server (legitimate clients only)

| phase | total pkts/s on LAN | SYN/s reaching server | legit handshake success | median SYN->SYN-ACK latency |
|---|---|---|---|---|
| before | 50 | 1.1 | 100% | 0.9 ms |
| during | 558 | 368.1 | 13% | 39.9 ms |
| after | 57 | 1.6 | 100% | 0.8 ms |
