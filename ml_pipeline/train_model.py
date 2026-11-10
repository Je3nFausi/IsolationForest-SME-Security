"""
train_model.py — Continuous Learning Retraining

- Loads raw data/real/*.csv (CICIDS2017) baseline.
- Connects to PostgreSQL to pull confirmed truth from SME feedback.
- Merges confirmed threats into the attack pool.
- Merges false alarms into the normal pool.
- Fits StandardScaler on the updated normal pool.
- Trains IsolationForest models.
- Saves updated models and scaler to disk.
"""
import json
import glob
import warnings
from pathlib import Path
import sys

import numpy as np
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from joblib import dump

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Database import
from database.db import get_connection

RAW_DIR = PROJECT_ROOT / "data" / "real"
MODEL_DIR = PROJECT_ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

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
    print(f"Total raw baseline rows: {len(full):,}")
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
    else:
        out["source_port"] = out["destination_port"]

    if "Label" not in df.columns:
        raise KeyError("Raw CICIDS missing 'Label' column.")
    out["is_attack"] = (df["Label"].astype(str).str.strip().str.upper() != "BENIGN").astype(int)

    before = len(out)
    out = out.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    print(f"Dropped {before - len(out):,} baseline rows (NaN/Inf). Remaining: {len(out):,}")
    return out


def load_feedback_truth():
    """
    Connects to PostgreSQL to pull the SME feedback.
    Returns two DataFrames: (confirmed_attacks, confirmed_normals)
    """
    print("\nConnecting to database to fetch SME feedback...")
    conn = get_connection()
    with conn.cursor() as cur:
        # 1. Fetch predictions where the user CONFIRMED a threat (Real attacks)
        # Note: We join on feedback.alert_id -> alerts.prediction_id -> predictions.id
        cur.execute("""
            SELECT p.*
            FROM predictions p
            JOIN alerts a ON p.id = a.prediction_id
            JOIN feedback f ON a.id = f.alert_id
            WHERE f.is_correct = TRUE
        """)
        confirmed_attacks = cur.fetchall()
        
        # 2. Fetch predictions where the user marked FALSE ALARM (Normal traffic)
        cur.execute("""
            SELECT p.*
            FROM predictions p
            JOIN alerts a ON p.id = a.prediction_id
            JOIN feedback f ON a.id = f.alert_id
            WHERE f.is_correct = FALSE
        """)
        confirmed_normals = cur.fetchall()
    conn.close()
    
    df_attacks = pd.DataFrame(confirmed_attacks) if confirmed_attacks else pd.DataFrame(columns=FEATURE_COLS)
    df_normals = pd.DataFrame(confirmed_normals) if confirmed_normals else pd.DataFrame(columns=FEATURE_COLS)
    
    print(f"Found {len(df_attacks)} confirmed threats from SME feedback.")
    print(f"Found {len(df_normals)} confirmed false alarms from SME feedback.")
    
    return df_attacks, df_normals


def main():
    # 1. Load the baseline
    raw = load_raw()
    df = derive_features(raw)

    normal = df[df["is_attack"] == 0]
    attacks = df[df["is_attack"] == 1]
    
    print(f"Baseline Normal rows: {len(normal):,} | Baseline Attack rows: {len(attacks):,}")

    # 2. Load the Truth from the database
    db_attacks, db_normals = load_feedback_truth()

    # 3. Merge the Truth
    if not db_attacks.empty:
        # Ensure the columns match
        db_attacks = db_attacks[FEATURE_COLS]
        db_attacks["is_attack"] = 1
        normal = pd.concat([normal, db_attacks], ignore_index=True) # Merge into normal? NO, into attacks.
        # Wait, the code above needs to merge into attacks, not normal.
        attacks = pd.concat([attacks, db_attacks], ignore_index=True)
        print(f"Added {len(db_attacks)} confirmed attacks to the training pool.")

    if not db_normals.empty:
        db_normals = db_normals[FEATURE_COLS]
        db_normals["is_attack"] = 0
        normal = pd.concat([normal, db_normals], ignore_index=True)
        print(f"Added {len(db_normals)} false alarms to the normal pool.")

    print(f"\nFinal Training Normal rows: {len(normal):,}")
    print(f"Final Training Attack rows: {len(attacks):,}")

    # 4. Train the model on the updated normal data
    X_normal = normal[FEATURE_COLS].values

    scaler = StandardScaler().fit(X_normal)
    X_scaled = scaler.transform(X_normal)

    dump(scaler, MODEL_DIR / "scaler.joblib")
    with open(MODEL_DIR / "feature_cols.json", "w") as f:
        json.dump(FEATURE_COLS, f)
    print(f"\nSaved updated scaler and feature_cols ({len(FEATURE_COLS)} features).")

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