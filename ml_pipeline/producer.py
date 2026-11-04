"""
producer.py — Simulates CICIDS2017-shaped network events → Kafka topic.

Publishes events with all 20 features the model expects.
Baseline (normal) rows are sampled from RAW CICIDS data (data/real/*.csv)
and features are derived using the SAME RAW_MAP as train_model.py — this
guarantees the producer emits exactly the schema the model was trained on.

Usage (from project root):
    python ml_pipeline/producer.py --rate 2 --anomaly-rate 0.05 --max-events 20

Stop with Ctrl+C.
"""
import argparse
import glob
import json
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from kafka import KafkaProducer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "real"

with open(PROJECT_ROOT / "models" / "feature_cols.json") as f:
    FEATURE_COLS = json.load(f)

# Same mapping as train_model.py — raw CICIDS column -> our feature name
RAW_MAP = {
    "Destination Port":              "destination_port",
    "Flow Duration":                 "duration",
    "Total Length of Fwd Packets":   "bytes_sent",
    "Total Length of Bwd Packets":   "bytes_received",
    "Total Fwd Packets":             "packets_sent",
    "Total Backward Packets":        "packets_received",
    "Packet Length Mean":            "packet_size",
    "Flow Bytes/s":                  "flow_bytes_per_s",
    "Flow Packets/s":                "flow_packets_per_s",
    "SYN Flag Count":                "syn_flag_count",
    "ACK Flag Count":                "ack_flag_count",
    "PSH Flag Count":                "psh_flag_count",
    "Fwd Packet Length Std":         "fwd_packet_len_std",
    "Bwd Packet Length Std":         "bwd_packet_len_std",
    "Average Packet Size":           "avg_packet_size",
    "Down/Up Ratio":                 "down_up_ratio",
    "Init_Win_bytes_forward":        "init_win_bytes_fwd",
    "Flow IAT Mean":                 "flow_iat_mean",
    "Flow IAT Std":                  "flow_iat_std",
}


def load_baseline_rows(n: int = 50000) -> pd.DataFrame:
    """
    Load a sample of REAL NORMAL CICIDS flows and derive the 20 features.
    Uses only Monday-WorkingHours (pure benign) if present, else filters
    by Label == BENIGN across all files.
    """
    files = sorted(glob.glob(str(RAW_DIR / "*.csv")))
    if not files:
        raise FileNotFoundError(f"No CSVs found in {RAW_DIR}")

    # Prefer Monday-WorkingHours (pure benign) for speed
    monday = [f for f in files if "Monday" in Path(f).name]
    use_files = monday if monday else files
    print(f"Loading baseline from {len(use_files)} raw file(s)...")

    per_file = max(1, n // len(use_files))
    frames = []
    for f in use_files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = [c.strip() if isinstance(c, str) else c for c in df.columns]
        # Filter to BENIGN only
        if "Label" in df.columns:
            df = df[df["Label"].astype(str).str.strip().str.upper() == "BENIGN"]
        # Derive features
        out = pd.DataFrame(index=df.index)
        for raw_col, feat in RAW_MAP.items():
            if raw_col not in df.columns:
                raise KeyError(f"Raw CICIDS missing '{raw_col}' in {Path(f).name}")
            out[feat] = pd.to_numeric(df[raw_col], errors="coerce")
        # source_port (mirror destination_port if missing)
        if "Source Port" in df.columns:
            out["source_port"] = pd.to_numeric(df["Source Port"], errors="coerce")
        else:
            out["source_port"] = out["destination_port"]
        out = out.replace([np.inf, -np.inf], np.nan).dropna()
        if len(out) > per_file:
            out = out.sample(n=per_file, random_state=42)
        frames.append(out)

    baseline = pd.concat(frames, ignore_index=True)
    missing = [c for c in FEATURE_COLS if c not in baseline.columns]
    if missing:
        raise KeyError(f"Derived baseline missing features: {missing}")
    baseline = baseline[FEATURE_COLS].reset_index(drop=True)
    print(f"Loaded {len(baseline):,} baseline normal rows")
    return baseline


def make_normal_event(baseline: pd.DataFrame) -> dict:
    row = baseline.sample(n=1).iloc[0]
    event = {col: float(row[col]) for col in FEATURE_COLS}
    event["event_id"] = str(uuid.uuid4())
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    event["ground_truth"] = "normal"
    return event


def make_anomaly_event(baseline: pd.DataFrame) -> dict:
    row = baseline.sample(n=1).iloc[0]
    event = {col: float(row[col]) for col in FEATURE_COLS}
    event["bytes_sent"] = float(np.random.uniform(50_000, 200_000))
    event["bytes_received"] = float(np.random.uniform(10, 500))
    event["flow_bytes_per_s"] = float(np.random.uniform(10_000, 100_000))
    event["duration"] = float(np.random.uniform(1, 50))
    event["packet_size"] = float(np.random.uniform(1_000, 3_000))
    event["event_id"] = str(uuid.uuid4())
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    event["ground_truth"] = "anomaly"
    return event


def main():
    parser = argparse.ArgumentParser(description="Simulate network events → Kafka")
    parser.add_argument("--broker", default="localhost:9092")
    parser.add_argument("--topic", default="network-events")
    parser.add_argument("--rate", type=float, default=2.0)
    parser.add_argument("--anomaly-rate", type=float, default=0.05)
    parser.add_argument("--max-events", type=int, default=0)
    args = parser.parse_args()

    baseline = load_baseline_rows()

    producer = KafkaProducer(
        bootstrap_servers=[args.broker],
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
        linger_ms=10,
    )
    print(f"Producer connected to {args.broker}, topic='{args.topic}'")
    print(f"Rate: {args.rate}/s  |  Anomaly rate: {args.anomaly_rate*100:.1f}%")
    print("Press Ctrl+C to stop.\n")

    sleep = 1.0 / args.rate
    sent = 0
    anomalies_sent = 0
    try:
        while True:
            is_anom = random.random() < args.anomaly_rate
            event = make_anomaly_event(baseline) if is_anom else make_normal_event(baseline)
            producer.send(args.topic, event)
            sent += 1
            if is_anom:
                anomalies_sent += 1
            tag = "⚠️  ANOMALY" if is_anom else "✅ normal "
            if args.max_events > 0 and sent >= args.max_events:
                break
            time.sleep(sleep)
    except KeyboardInterrupt:
        print("\nStopping producer...")
    finally:
        producer.flush()
        producer.close()
        print(f"\nSent {sent} events ({anomalies_sent} anomalies).")


if __name__ == "__main__":
    main()