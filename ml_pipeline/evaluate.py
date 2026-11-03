"""
evaluate.py — Step 1 diagnostic: per-attack-family breakdown

- Re-derives 20 features from raw data/real/*.csv
- Uses saved scaler + each contamination model
- Prints precision/recall per CICIDS attack family (per tier)

Run from project root:
    python ml_pipeline/evaluate.py
"""
import json
import glob
import warnings
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
from joblib import load
from sklearn.metrics import precision_score, recall_score, f1_score

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "real"
MODEL_DIR = PROJECT_ROOT / "models"

with open(MODEL_DIR / "feature_cols.json") as f:
    FEATURE_COLS = json.load(f)
scaler = load(MODEL_DIR / "scaler.joblib")

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

CONTAMINATIONS = [0.01, 0.02, 0.05, 0.10]


def load_and_derive():
    files = sorted(glob.glob(str(RAW_DIR / "*.csv")))
    frames = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = [c.strip() if isinstance(c, str) else c for c in df.columns]
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)

    out = pd.DataFrame(index=df.index)
    for raw_col, feat in RAW_MAP.items():
        out[feat] = pd.to_numeric(df[raw_col], errors="coerce")
    if "Source Port" in df.columns:
        out["source_port"] = pd.to_numeric(df["Source Port"], errors="coerce")
    else:
        out["source_port"] = out["destination_port"]
    label_raw = df["Label"].astype(str).str.strip()
    out["label"] = label_raw
    out["is_attack"] = (label_raw.str.upper() != "BENIGN").astype(int)
    out = out.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    return out


def summarize_families(df, tier_name, train_frac, model, contamination):
    normal = df[df["is_attack"] == 0].reset_index(drop=True)
    attack = df[df["is_attack"] == 1].reset_index(drop=True)

    n_train = int(len(normal) * train_frac)
    normal_eval = normal.iloc[n_train:]
    if len(normal_eval) == 0:
        normal_eval = normal

    # normal baseline for precision context
    Xn = scaler.transform(normal_eval[FEATURE_COLS].values)
    pred_n = model.predict(Xn)
    normal_flags = int((pred_n == -1).sum())
    print(f"\n=== {tier_name} | contamination={contamination} ===")
    print(f"  Normal eval rows: {len(normal_eval):,}  | flagged as anomaly: {normal_flags:,} "
          f"({normal_flags/max(len(normal_eval),1)*100:.2f}% false positive rate)")

    # per attack family
    families = attack["label"].unique()
    print(f"  {'family':30s} {'rows':>10s} {'caught':>10s} {'recall':>8s}")
    for fam in sorted(families):
        sub = attack[attack["label"] == fam]
        if len(sub) == 0:
            continue
        Xa = scaler.transform(sub[FEATURE_COLS].values)
        pred_a = model.predict(Xa)
        caught = int((pred_a == -1).sum())
        recall = caught / len(sub)
        print(f"  {fam[:30]:30s} {len(sub):>10,} {caught:>10,} {recall:>8.3f}")

    # overall P/R/F1 for reference
    X_all = scaler.transform(pd.concat([normal_eval, attack], ignore_index=True)[FEATURE_COLS].values)
    y_true = np.array([1] * len(normal_eval) + [-1] * len(attack))
    y_pred = model.predict(X_all)
    p = precision_score(y_true, y_pred, pos_label=-1, zero_division=0)
    r = recall_score(y_true, y_pred, pos_label=-1, zero_division=0)
    f = f1_score(y_true, y_pred, pos_label=-1, zero_division=0)
    print(f"  OVERALL: P={p:.3f}  R={r:.3f}  F1={f:.3f}")


def main():
    df = load_and_derive()
    print(f"Total rows: {len(df):,}")
    print(f"Attack families present:")
    print(df[df["is_attack"] == 1]["label"].value_counts().to_string())

    models = {}
    for c in CONTAMINATIONS:
        path = MODEL_DIR / f"if_contam_{str(c).replace('.', '_')}.joblib"
        if not path.exists():
            raise FileNotFoundError(f"Missing model: {path}. Run train_model.py first.")
        models[c] = load(path)

    # Report only contamination=0.05 (the best from the previous sweep)
    best_c = 0.05
    model = models[best_c]
    for tier, frac in [("small", 0.10), ("medium", 0.40), ("large", 0.80)]:
        summarize_families(df, tier, frac, model, best_c)


if __name__ == "__main__":
    main()