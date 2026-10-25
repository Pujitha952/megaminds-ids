"""Unsupervised anomaly layer: Isolation Forest trained on BENIGN traffic only.

Why: signatures only catch what we wrote rules for. Trained on normal behaviour, the model flags
windows that look unlike anything seen in benign traffic (including attack types with no rule).
Threshold is calibrated on a separate benign validation capture to cap the false-positive rate.
"""
from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .features import ML_FEATURES

# minimum "unit" per feature so near-constant benign features don't give absurd z-scores
SCALE_FLOOR = {"pps": 1.0, "bytes_per_s": 500.0, "avg_pkt_size": 20.0, "unique_dst_ips": 1.0,
               "new_conns": 1.0, "fail_ratio": 0.1, "max_ports_per_target": 1.0,
               "max_conns_per_target": 1.0, "arp_unsolicited": 1.0}


class AnomalyModel:
    def __init__(self, n_estimators: int = 300, seed: int = 0):
        self.iforest = IsolationForest(n_estimators=n_estimators, contamination="auto", random_state=seed)
        self.threshold = 0.0
        self.median = None
        self.scale = None

    def _X(self, df: pd.DataFrame) -> np.ndarray:
        return df[ML_FEATURES].to_numpy(dtype=float)

    def fit(self, train_df: pd.DataFrame):
        X = self._X(train_df)
        self.iforest.fit(X)
        self.median = np.median(X, axis=0)
        std = X.std(axis=0)
        self.scale = np.maximum(std, [SCALE_FLOOR[f] for f in ML_FEATURES])
        self.threshold = float(self.score(train_df).max())      # provisional until calibrate()
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        """Anomaly score: higher = more anomalous."""
        return -self.iforest.score_samples(self._X(df))

    def calibrate(self, val_df: pd.DataFrame, target_fpr: float = 0.002, margin: float = 0.01):
        """Threshold = (1 - target_fpr) quantile of benign validation scores + small margin."""
        s = self.score(val_df)
        self.threshold = float(np.quantile(s, 1 - target_fpr) + margin)
        return self

    def flag(self, df: pd.DataFrame):
        s = self.score(df)
        return s, s > self.threshold

    def explain(self, row: pd.Series, top: int = 3):
        """Features that deviate most from the benign baseline (robust z-score)."""
        x = row[ML_FEATURES].to_numpy(dtype=float)
        z = (x - self.median) / self.scale
        order = np.argsort(-np.abs(z))[:top]
        return [{"feature": ML_FEATURES[i], "value": round(float(x[i]), 2),
                 "benign_median": round(float(self.median[i]), 2), "z": round(float(z[i]), 1)}
                for i in order if abs(z[i]) >= 1.0]

    def save(self, path: str):
        joblib.dump(self, path)

    @staticmethod
    def load(path: str) -> "AnomalyModel":
        return joblib.load(path)
