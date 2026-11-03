"""
train_model.py — Step 1 (Path A: expanded features, contamination sweep)

- Loads raw data/real/*.csv (CICIDS2017)
- Derives 20 features (8 original + 12 CICIDS discriminators)
- Fits StandardScaler on NORMAL-ONLY rows
- Trains one IsolationForest per contamination in [0.01, 0.02, 0.05, 0.10]
- Saves: models/if_contam_{c}.joblib, models/scaler.joblib, models/feature_cols.json

Run from project root:
    python ml_pipeline/train_model.py
"""
import json
import glob
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from joblib import dump

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "real"
MODEL_DIR = PROJECT_ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

# Raw CICIDS column (stripped) -> our feature name
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

# Final feature order (source_port inserted separately)
FEATURE_COLS = [
    "source_port", "destination_port", "duration",
    "bytes_sent", "bytes_received", "packets_sent",
    "packets_received", "packet_size",
    "flow_bytes_per_s", "flow_packets_per_s",
    "syn_flag_count", "ack_flag_count", "psh_flag_count",
    "fwd_packet_len_std", "bwd_packet_len_std",
    "avg_packet_size", "down_up_ratio",
    "init_win_bytes_fwd", "flow_iat_mean", "flow_iat_std",
]

CONTAMINATIONS = [0.01, 0.02, 0.05, 0.10]


def load_raw():
    files = sorted(glob.glob(str(RAW_DIR / "*.csv")))
    if not files:
        raise FileNotFoundError(f"No CSVs in {RAW_DIR}")
    print(f"Loading {len(files)} raw CICIDS file(s)...")
    frames = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = [c.strip() if isinstance(c, str) else c for c in df.columns]
        frames.append(df)
    full = pd.concat(frames, ignore_index=True)
    print(f"Total raw rows: {len(full):,}")
    return full


def derive_features(df: pd.DataFrame) -> pd.DataFrame:
    missing = [k for k in RAW_MAP if k not in df.columns]
    if missing:
        raise KeyError(f"Raw CICIDS missing expected columns: {missing}")

    out = pd.DataFrame(index=df.index)
    for raw_col, feat in RAW_MAP.items():
        out[feat] = pd.to_numeric(df[raw_col], errors="coerce")

    if "Source Port" in df.columns:
        out["source_port"] = pd.to_numeric(df["Source Port"], errors="coerce")
        print("source_port: from raw 'Source Port'.")
    else:
        out["source_port"] = out["destination_port"]
        print("source_port: WARNING — mirrored destination_port (no Source Port in raw).")

    if "Label" not in df.columns:
        raise KeyError("Raw CICIDS missing 'Label' column.")
    out["is_attack"] = (df["Label"].astype(str).str.strip().str.upper() != "BENIGN").astype(int)

    before = len(out)
    out = out.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    print(f"Dropped {before - len(out):,} rows (NaN/Inf). Remaining: {len(out):,}")
    return out


def main():
    raw = load_raw()
    df = derive_features(raw)

    normal = df[df["is_attack"] == 0]
    n_attack = int(df["is_attack"].sum())
    print(f"Normal rows: {len(normal):,} | Attack rows: {n_attack:,}")

    X_normal = normal[FEATURE_COLS].values

    scaler = StandardScaler().fit(X_normal)
    X_scaled = scaler.transform(X_normal)

    dump(scaler, MODEL_DIR / "scaler.joblib")
    with open(MODEL_DIR / "feature_cols.json", "w") as f:
        json.dump(FEATURE_COLS, f)
    print(f"\nSaved scaler and feature_cols ({len(FEATURE_COLS)} features).")

    for c in CONTAMINATIONS:
        print(f"Training IsolationForest (contamination={c}) ...")
        model = IsolationForest(
            n_estimators=200,
            contamination=c,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_scaled)
        path = MODEL_DIR / f"if_contam_{str(c).replace('.', '_')}.joblib"
        dump(model, path)
        print(f"  -> {path.name}")


if __name__ == "__main__":
    main()