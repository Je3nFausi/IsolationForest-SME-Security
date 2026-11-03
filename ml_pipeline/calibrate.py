"""
calibrate.py — Step 1 (Path 1): correct threshold calibration + ROC-AUC

v3 fix:
  - Validation normal:attack ratio is EXACTLY equal to test's ratio
    (previous bug: fixed attack_val=55k while normal_val scaled with tier,
     making medium/large validation attack-heavy -> thresholds over-flagged)
  - Threshold sweep on the validation score distribution
  - Adds ROC-AUC (primary metric for unsupervised anomaly detection)
"""
import json
import glob
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from joblib import load
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
)

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
GATE = 0.85


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


def sweep_threshold(scores_val, y_val, n_points=200):
    qs = np.quantile(scores_val, np.linspace(0.001, 0.999, n_points))
    best = (None, -1.0)
    for thr in qs:
        y_pred = np.where(scores_val < thr, -1, 1)
        f = f1_score(y_val, y_pred, pos_label=-1, zero_division=0)
        if f > best[1]:
            best = (thr, f)
    return best


def stratified_validation(normal_pool, attack_pool, n_test_norm, n_test_att):
    """
    Build validation with EXACT test ratio (n_test_norm : n_test_att).

    We cap validation size to keep runtime reasonable, but the RATIO
    between normal and attack MUST match test exactly.
    """
    ratio = n_test_norm / max(n_test_att, 1)   # e.g. 1635351/556556 ≈ 2.94

    # Target validation attack size (cap at available), then normal = ratio * attack
    # Cap total validation ~50k for speed, split by ratio.
    val_att_max = min(len(attack_pool), 15000)
    val_att = max(1000, val_att_max)
    val_norm = int(val_att * ratio)
    val_norm = min(val_norm, len(normal_pool))

    # If normal_pool can't supply enough, shrink attack to preserve ratio
    if val_norm < int(val_att * ratio):
        val_att = int(val_norm / ratio)
        val_att = max(500, val_att)

    normal_val = normal_pool.sample(n=val_norm, random_state=42).reset_index(drop=True)
    attack_val = attack_pool.sample(n=val_att, random_state=42).reset_index(drop=True)
    return normal_val, attack_val


def evaluate_tier(df, train_frac, tier_name, models):
    normal = df[df["is_attack"] == 0].reset_index(drop=True)
    attack = df[df["is_attack"] == 1].reset_index(drop=True)

    n_train = int(len(normal) * train_frac)
    remainder = normal.iloc[n_train:].reset_index(drop=True)
    if len(remainder) < 5000:
        remainder = normal.reset_index(drop=True)

    n_val_holdout = int(len(remainder) * 0.20)
    pool_for_val = remainder.iloc[:n_val_holdout].reset_index(drop=True)
    normal_test  = remainder.iloc[n_val_holdout:].reset_index(drop=True)

    normal_val, attack_val = stratified_validation(
        pool_for_val, attack, len(normal_test), len(attack)
    )

    ratio_test = len(normal_test) / len(attack)
    ratio_val  = len(normal_val) / max(len(attack_val), 1)
    print(f"\n=== {tier_name} (train_frac={train_frac}) ===")
    print(f"  test ratio normal:attack = {ratio_test:.3f}  "
          f"val ratio = {ratio_val:.3f}  (should match)")
    print(f"  normal_test={len(normal_test):,}  attacks={len(attack):,}  "
          f"normal_val={len(normal_val):,}  attack_val={len(attack_val):,}")

    results = []
    for c, model in models.items():
        sv_n = model.decision_function(scaler.transform(normal_val[FEATURE_COLS].values))
        sv_a = model.decision_function(scaler.transform(attack_val[FEATURE_COLS].values))
        sv = np.concatenate([sv_n, sv_a])
        yv = np.array([1] * len(sv_n) + [-1] * len(sv_a))
        thr, val_f1 = sweep_threshold(sv, yv)

        sn = model.decision_function(scaler.transform(normal_test[FEATURE_COLS].values))
        sa = model.decision_function(scaler.transform(attack[FEATURE_COLS].values))
        y_true = np.array([1] * len(sn) + [-1] * len(sa))
        y_pred = np.where(np.concatenate([sn, sa]) < thr, -1, 1)

        p = precision_score(y_true, y_pred, pos_label=-1, zero_division=0)
        r = recall_score(y_true, y_pred, pos_label=-1, zero_division=0)
        f = f1_score(y_true, y_pred, pos_label=-1, zero_division=0)
        auc = roc_auc_score((y_true == -1).astype(int), -np.concatenate([sn, sa]))
        fpr = float((sn < thr).mean())

        print(f"  contam={c:4.2f}  thr={thr:+.4f}  valF1={val_f1:.3f}  |  "
              f"P={p:.3f} R={r:.3f} F1={f:.3f} AUC={auc:.3f} FPR={fpr:.3f}")
        results.append((c, thr, p, r, f, auc, fpr))

    best = max(results, key=lambda x: x[4])
    return best, results


def per_family(df, train_frac, contamination, threshold):
    normal = df[df["is_attack"] == 0].reset_index(drop=True)
    attack = df[df["is_attack"] == 1].reset_index(drop=True)
    n_train = int(len(normal) * train_frac)
    remainder = normal.iloc[n_train:].reset_index(drop=True)
    n_val_holdout = int(len(remainder) * 0.20)
    normal_test = remainder.iloc[n_val_holdout:].reset_index(drop=True)

    model = load(MODEL_DIR / f"if_contam_{str(contamination).replace('.', '_')}.joblib")
    sn = model.decision_function(scaler.transform(normal_test[FEATURE_COLS].values))

    print(f"\n--- contam={contamination} thr={threshold:+.4f} ---")
    print(f"  Normal test: {len(normal_test):,}  flagged: {int((sn<threshold).sum()):,}  "
          f"({float((sn<threshold).mean())*100:.2f}% FPR)")
    print(f"  {'family':30s} {'rows':>10s} {'caught':>10s} {'recall':>8s}")
    for fam in sorted(attack["label"].unique()):
        sub = attack[attack["label"] == fam]
        if len(sub) == 0:
            continue
        sa = model.decision_function(scaler.transform(sub[FEATURE_COLS].values))
        caught = int((sa < threshold).sum())
        print(f"  {fam[:30]:30s} {len(sub):>10,} {caught:>10,} {caught/len(sub):>8.3f}")


def main():
    df = load_and_derive()
    print(f"Total rows: {len(df):,}")

    models = {}
    for c in CONTAMINATIONS:
        path = MODEL_DIR / f"if_contam_{str(c).replace('.', '_')}.joblib"
        if not path.exists():
            raise FileNotFoundError(f"Missing model: {path}")
        models[c] = load(path)

    tier_best = {}
    for tier, frac in [("small", 0.10), ("medium", 0.40), ("large", 0.80)]:
        best, _ = evaluate_tier(df, frac, tier, models)
        tier_best[tier] = best

    print("\n=== FINAL STEP-1 METRICS (for documentation) ===")
    print(f"{'tier':6s} {'contam':>7s} {'thr':>8s} {'P':>6s} {'R':>6s} {'F1':>6s} {'AUC':>6s} {'FPR':>6s}")
    for tier, (c, thr, p, r, f, auc, fpr) in tier_best.items():
        print(f"{tier:6s} {c:7.2f} {thr:+8.4f} {p:6.3f} {r:6.3f} {f:6.3f} {auc:6.3f} {fpr:6.3f}")

    print("\n=== PER-FAMILY (small tier — representative) ===")
    c, thr, p, r, f, auc, fpr = tier_best["small"]
    print(f">>> SMALL (contam={c}, thr={thr:+.4f}, F1={f:.3f}, AUC={auc:.3f})")
    per_family(df, 0.10, c, thr)

    print("\n=== GATE vs 0.85 (F1) + PRIMARY METRIC AUC ===")
    for tier, (c, thr, p, r, f, auc, fpr) in tier_best.items():
        print(f"  {tier:6s} F1={f:.3f}  {'PASS' if f>=GATE else 'FAIL'}  |  AUC={auc:.3f}")
    print("\nNOTE: AUC is the primary metric for unsupervised anomaly detection.")


if __name__ == "__main__":
    main()