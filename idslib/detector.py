"""Hybrid detector: rule layer + Isolation Forest, merged into one explainable alert list.

Merge policy (per window+source):
  * rule fired            -> alert keeps the rule's category/reason; if the ML layer ALSO flagged the
                             window it is upgraded to detector="rule+ml" (+0.05 confidence) - two
                             independent layers agreeing.
  * only ML flagged       -> category "ANOMALY": we know it is unusual, not what it is. Severity is
                             capped at Medium and the reason lists the features that deviate most.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

from .features import Capture, extract
from .ml import AnomalyModel
from .rules import apply_rules

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(ROOT, "models", "iforest.joblib")
MODES = ("rules", "ml", "hybrid")


class Result:
    def __init__(self, cap: Capture, alerts: List[dict], mode: str, scores: Optional[np.ndarray]):
        self.cap, self.alerts, self.mode, self.scores = cap, alerts, mode, scores

    def alerts_df(self) -> pd.DataFrame:
        cols = ["id", "t_start", "src", "dst", "category", "severity", "confidence", "detector", "why"]
        if not self.alerts:
            return pd.DataFrame(columns=cols)
        return pd.DataFrame(self.alerts)[cols]


def train(train_pcap: str, val_pcap: str, out: str = MODEL_PATH, window: float = 5.0,
          target_fpr: float = 0.002) -> AnomalyModel:
    m = AnomalyModel().fit(extract(train_pcap, window).df)
    m.calibrate(extract(val_pcap, window).df, target_fpr=target_fpr)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    m.save(out)
    return m


def _ml_alerts(cap: Capture, model: AnomalyModel):
    scores, flagged = model.flag(cap.df)
    out = {}
    for i in np.flatnonzero(flagged):
        row = cap.df.iloc[i]
        dev = model.explain(row)
        margin = float(scores[i] - model.threshold)
        sev = "Medium" if margin > 0.05 else "Low"
        conf = round(float(np.clip(0.5 + 3 * margin, 0.5, 0.9)), 2)
        txt = "; ".join(f"{d['feature']}={d['value']} (benign median {d['benign_median']}, z={d['z']:+.1f})" for d in dev)
        out[(int(row.window), row.src)] = {
            "window": int(row.window), "t_start": float(row.t_start), "src": row.src, "dst": row.top_target or row.scan_target,
            "detector": "ml", "category": "ANOMALY", "severity": sev, "confidence": conf,
            "why": (f"Isolation-Forest score {scores[i]:.3f} > benign-calibrated threshold {model.threshold:.3f}; "
                    f"most unusual features: {txt or 'n/a'}"),
            "evidence": {"score": round(float(scores[i]), 3), "threshold": round(model.threshold, 3), "deviations": dev}}
    return scores, out


def detect(pcap: str, mode: str = "hybrid", window: float = 5.0, model_path: str = MODEL_PATH,
           arp_bindings: Optional[Dict[str, str]] = None, rule_thresholds: Optional[dict] = None,
           cap: Optional[Capture] = None) -> Result:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    cap = cap or extract(pcap, window)
    rule_alerts = apply_rules(cap, rule_thresholds, arp_bindings) if mode in ("rules", "hybrid") else []
    scores, ml_map = (None, {})
    if mode in ("ml", "hybrid"):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"{model_path} not found - run: python ids.py train")
        scores, ml_map = _ml_alerts(cap, AnomalyModel.load(model_path))
    alerts: List[dict] = []
    used = set()
    for a in rule_alerts:
        k = (a["window"], a["src"])
        if mode == "hybrid" and k in ml_map:
            a = {**a, "detector": "rule+ml", "confidence": min(0.99, round(a["confidence"] + 0.05, 2))}
            a["evidence"] = {**a["evidence"], "ml_score": ml_map[k]["evidence"]["score"]}
            used.add(k)
        alerts.append(a)
    if mode == "ml":
        alerts = list(ml_map.values())
    elif mode == "hybrid":
        alerts += [v for k, v in ml_map.items() if k not in used and not any(
            (x["window"], x["src"]) == k for x in alerts)]
    alerts.sort(key=lambda a: (a["window"], a["src"], a["category"]))
    for i, a in enumerate(alerts, 1):
        a["id"] = i
    return Result(cap, alerts, mode, scores)
