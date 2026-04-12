import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from joblib import dump, load
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from soc_db import SocAnalyticsDB, parse_float


def utc_ms_now() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


def _proto_to_int(proto: str) -> int:
    p = (proto or "").lower().strip()
    if p == "tcp":
        return 0
    if p == "udp":
        return 1
    if p == "icmp":
        return 2
    return 3


@dataclass
class MlConfig:
    model_path: str
    retrain_min_interval_sec: int = 300  # 5 minutes
    min_normal_train_samples: int = 80
    min_malicious_samples: int = 20
    pseudo_normal_batch: int = 400
    pseudo_threshold_normal: float = 0.20  # decision_function > this => normal
    pseudo_threshold_malicious_margin: float = 0.0  # decision_function < (threshold + margin)
    random_state: int = 42


class SelfTrainingAnomalyModel:
    """
    IsolationForest-based self-training:
    - Train IF on "normal" flows (initially labeled normals or unlabeled fallback).
    - Hard-label "malicious" flows using alerts (flow<->alert linking in DB).
    - Self-train by promoting high-confidence unlabeled flows to normal/malicious pseudo-labels.
    """

    def __init__(self, *, db: SocAnalyticsDB, config: MlConfig):
        self.db = db
        self.cfg = config
        self._lock = threading.Lock()
        self._model: Optional[Any] = None  # pipeline
        self._decision_threshold: float = 0.0  # decision_function < threshold => malicious
        self._feature_version: int = 1
        self._last_trained_ms: int = 0

        self._load_if_exists()

    def _load_if_exists(self) -> None:
        p = Path(self.cfg.model_path)
        if not p.exists():
            return
        try:
            payload = load(self.cfg.model_path)
            self._model = payload.get("pipeline")
            self._decision_threshold = float(payload.get("decision_threshold", 0.0))
            self._feature_version = int(payload.get("feature_version", 1))
            self._last_trained_ms = int(payload.get("trained_at_ms", 0))
        except Exception:
            # Keep system running; training will attempt later.
            self._model = None

    def is_ready(self) -> bool:
        return self._model is not None

    def predict_flow(self, *, flow_features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Returns anomaly prediction for a flow feature vector.
        """
        if not self._model:
            return None
        try:
            x = np.array(
                [[
                    float(flow_features["bytes_toserver"]),
                    float(flow_features["pkts_toserver"]),
                    float(flow_features["dest_port"]),
                    _proto_to_int(flow_features["proto"]),
                    float(flow_features["flow_duration"]),
                ]],
                dtype=float,
            )
            score = float(self._model.decision_function(x)[0])
            is_malicious = score < self._decision_threshold
            margin = self._decision_threshold - score  # positive when malicious

            return {
                "decision_function": score,
                "decision_threshold": self._decision_threshold,
                "is_malicious": bool(is_malicious),
                "margin": float(margin),
            }
        except Exception:
            return None

    def _load_flow_dataframe(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        conn = self.db.connect()
        cur = conn.cursor()
        # Use only rows with required numeric columns populated.
        cur.execute(
            """
            SELECT id, ts_ms, src_ip, dest_ip, src_port, dest_port, proto,
                   bytes_toserver, pkts_toserver, flow_duration, state,
                   labeled_status
            FROM flow_events
            WHERE bytes_toserver IS NOT NULL
              AND pkts_toserver IS NOT NULL
              AND dest_port IS NOT NULL
              AND flow_duration IS NOT NULL
              AND proto IS NOT NULL AND proto != ''
            """
        )
        rows = cur.fetchall()
        if not rows:
            return pd.DataFrame(), pd.DataFrame()
        df = pd.DataFrame([dict(r) for r in rows])
        if df.empty:
            return pd.DataFrame(), pd.DataFrame()

        labeled = df[df["labeled_status"].isin(["normal", "malicious"])].copy()
        unlabeled = df[df["labeled_status"] == "unlabeled"].copy()
        return labeled, unlabeled

    def train_if_needed(self, *, run_training_reason: str = "periodic") -> bool:
        """
        Retrains model if enough new data and the minimum interval passed.
        Returns True if model retrained.
        """
        with self._lock:
            now_ms = utc_ms_now()
            if self._last_trained_ms and (now_ms - self._last_trained_ms) < self.cfg.retrain_min_interval_sec * 1000:
                return False

            labeled_df, unlabeled_df = self._load_flow_dataframe()
            if labeled_df.empty and unlabeled_df.empty:
                return False

            # Normal train candidates:
            normal_df = labeled_df[labeled_df["labeled_status"] == "normal"].copy()
            if len(normal_df) < self.cfg.min_normal_train_samples:
                # Fallback: treat unlabeled as normal to bootstrap.
                normal_df = pd.concat([normal_df, unlabeled_df], ignore_index=True)

            if len(normal_df) < self.cfg.min_normal_train_samples:
                return False

            X_train = np.column_stack(
                [
                    normal_df["bytes_toserver"].astype(float).values,
                    normal_df["pkts_toserver"].astype(float).values,
                    normal_df["dest_port"].astype(float).values,
                    normal_df["proto"].apply(_proto_to_int).astype(float).values,
                    normal_df["flow_duration"].astype(float).values,
                ]
            )

            pipeline = Pipeline(
                steps=[
                    ("scaler", StandardScaler()),
                    (
                        "model",
                        IsolationForest(
                            n_estimators=250,
                            contamination="auto",
                            random_state=self.cfg.random_state,
                        ),
                    ),
                ]
            )
            pipeline.fit(X_train)

            # Threshold calibration from labeled data if possible.
            threshold = 0.0
            malicious_df = labeled_df[labeled_df["labeled_status"] == "malicious"].copy()
            if len(malicious_df) >= self.cfg.min_malicious_samples and len(normal_df) > 0:
                X_mal = np.column_stack(
                    [
                        malicious_df["bytes_toserver"].astype(float).values,
                        malicious_df["pkts_toserver"].astype(float).values,
                        malicious_df["dest_port"].astype(float).values,
                        malicious_df["proto"].apply(_proto_to_int).astype(float).values,
                        malicious_df["flow_duration"].astype(float).values,
                    ]
                )
                X_nor = np.column_stack(
                    [
                        normal_df["bytes_toserver"].astype(float).values,
                        normal_df["pkts_toserver"].astype(float).values,
                        normal_df["dest_port"].astype(float).values,
                        normal_df["proto"].apply(_proto_to_int).astype(float).values,
                        normal_df["flow_duration"].astype(float).values,
                    ]
                )
                y_true = np.array([1] * len(malicious_df) + [0] * len(normal_df))  # 1=malicious
                scores = pipeline.decision_function(np.vstack([X_mal, X_nor]))

                # Scan thresholds to maximize F1 for malicious.
                candidate_thresholds = np.unique(scores)
                best_thr = candidate_thresholds[0] if len(candidate_thresholds) else 0.0
                best_f1 = -1.0
                for thr in candidate_thresholds:
                    y_pred = (scores < thr).astype(int)  # malicious when decision < thr
                    tp = int(((y_pred == 1) & (y_true == 1)).sum())
                    fp = int(((y_pred == 1) & (y_true == 0)).sum())
                    fn = int(((y_pred == 0) & (y_true == 1)).sum())
                    precision = tp / max(1, tp + fp)
                    recall = tp / max(1, tp + fn)
                    f1 = 2 * precision * recall / max(1e-9, precision + recall)
                    if f1 > best_f1:
                        best_f1 = f1
                        best_thr = float(thr)
                threshold = float(best_thr)
            else:
                # No (enough) malicious labels yet: treat bottom 5% as anomalous.
                scores_n = pipeline.decision_function(X_train)
                threshold = float(np.quantile(scores_n, 0.05))

            # Self-training promotion for unlabeled samples.
            # Promote most confident normals to labeled_status='normal'.
            pseudo_updated = {"promoted_normal": 0, "promoted_malicious": 0}
            if not unlabeled_df.empty:
                # Predict on a limited subset to keep training bounded.
                cand = unlabeled_df.tail(5000).copy()
                X_cand = np.column_stack(
                    [
                        cand["bytes_toserver"].astype(float).values,
                        cand["pkts_toserver"].astype(float).values,
                        cand["dest_port"].astype(float).values,
                        cand["proto"].apply(_proto_to_int).astype(float).values,
                        cand["flow_duration"].astype(float).values,
                    ]
                )
                scores_c = pipeline.decision_function(X_cand)
                cand = cand.assign(decision_function=scores_c)

                normal_cand = cand[cand["decision_function"] > self.cfg.pseudo_threshold_normal].sort_values(
                    "decision_function", ascending=False
                )
                normal_ids = normal_cand.head(self.cfg.pseudo_normal_batch)["id"].astype(int).tolist()

                # Pseudo malicious only when we already have some malicious labels (avoid snowballing early).
                malicious_ids: List[int] = []
                if len(malicious_df) >= self.cfg.min_malicious_samples:
                    mal_cand = cand[cand["decision_function"] < (threshold - self.cfg.pseudo_threshold_malicious_margin)].sort_values(
                        "decision_function", ascending=True
                    )
                    malicious_ids = mal_cand.head(self.cfg.pseudo_normal_batch)["id"].astype(int).tolist()

                conn = self.db.connect()
                cur = conn.cursor()
                now_ms = utc_ms_now()

                if normal_ids:
                    cur.executemany(
                        """
                        UPDATE flow_events
                        SET labeled_status = 'normal',
                            label_source = 'pseudo',
                            updated_at_ms = ?
                        WHERE id = ?
                        """,
                        [(now_ms, i) for i in normal_ids],
                    )
                    pseudo_updated["promoted_normal"] = len(normal_ids)
                if malicious_ids:
                    cur.executemany(
                        """
                        UPDATE flow_events
                        SET labeled_status = 'malicious',
                            label_source = 'pseudo',
                            updated_at_ms = ?
                        WHERE id = ?
                        """,
                        [(now_ms, i) for i in malicious_ids],
                    )
                    pseudo_updated["promoted_malicious"] = len(malicious_ids)
                if normal_ids or malicious_ids:
                    conn.commit()

            payload = {
                "pipeline": pipeline,
                "decision_threshold": threshold,
                "trained_at_ms": now_ms,
                "feature_version": self._feature_version,
                "cfg": {
                    "retrain_min_interval_sec": self.cfg.retrain_min_interval_sec,
                    "min_normal_train_samples": self.cfg.min_normal_train_samples,
                    "min_malicious_samples": self.cfg.min_malicious_samples,
                    "pseudo_normal_batch": self.cfg.pseudo_normal_batch,
                    "pseudo_threshold_normal": self.cfg.pseudo_threshold_normal,
                },
                "self_training": pseudo_updated,
                "reason": run_training_reason,
            }
            Path(self.cfg.model_path).parent.mkdir(parents=True, exist_ok=True)
            dump(payload, self.cfg.model_path)

            self._model = pipeline
            self._decision_threshold = float(threshold)
            self._last_trained_ms = now_ms

            meta = {
                "trained_at_ms": now_ms,
                "decision_threshold": threshold,
                "feature_version": self._feature_version,
                "reason": run_training_reason,
                "self_training": pseudo_updated,
                "counts": {
                    "labeled_total": int(len(labeled_df)),
                    "normal_labeled": int(len(labeled_df[labeled_df["labeled_status"] == "normal"])),
                    "malicious_labeled": int(len(labeled_df[labeled_df["labeled_status"] == "malicious"])),
                    "unlabeled_total": int(len(unlabeled_df)),
                },
            }
            self.db.update_ml_state(key="latest_training", value=meta)
            return True


def explain_zabbix_alert(alert: Dict[str, Any]) -> str:
    """
    Rule-based explanation for Zabbix triggers used by AI Analyst tab.
    """
    trigger = str(alert.get("trigger_name") or "").lower()
    severity = str(alert.get("severity") or "Information")
    host = str(alert.get("hostname") or "unknown host")

    if "passwd" in trigger:
        return (
            f"Trigger on {host}: '/etc/passwd' changed. This may indicate unauthorized account manipulation or privilege escalation. "
            f"Severity={severity}. Recommended actions: verify recent admin commands, check file integrity baseline, review SSH auth logs, and rotate credentials."
        )
    if "cpu" in trigger:
        return (
            f"Trigger on {host}: unusual CPU utilization. This can signal DoS load, malware execution, or runaway processes. "
            f"Severity={severity}. Recommended actions: inspect top processes, correlate with network spikes, and isolate suspicious workloads."
        )
    if "memory" in trigger or "ram" in trigger:
        return (
            f"Trigger on {host}: memory pressure detected. This may degrade services and hide malicious resource abuse. "
            f"Severity={severity}. Recommended actions: inspect process memory usage, restart unhealthy services, and check for suspicious binaries."
        )
    if "net.if" in trigger or "network" in trigger or "zttqhuceey" in trigger:
        return (
            f"Trigger on {host}: abnormal network traffic. This can indicate scanning, exfiltration, or C2 communication. "
            f"Severity={severity}. Recommended actions: inspect active connections, block suspicious destinations, and capture packets for forensics."
        )
    return (
        f"Trigger on {host}: '{alert.get('trigger_name', 'Unknown trigger')}'. Potential security impact depends on service criticality. "
        f"Severity={severity}. Recommended actions: validate trigger context, correlate with recent changes, and apply containment if compromise signs exist."
    )

