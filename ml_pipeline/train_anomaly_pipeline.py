"""
Train the BI-Safe anomaly pipeline.

Usage (from the project root):
    python -m ml_pipeline.train_anomaly_pipeline --size small

Loads data/synthetic/synthetic_<size>.csv, trains a Pipeline
(ColumnTransformer + IsolationForest) on a stratified 80% split,
evaluates on the held-out 20% using is_attack, and saves the fitted
Pipeline to models/anomaly_pipeline_<size>.joblib.
"""

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from ml_pipeline.preprocessing import build_preprocessor

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "synthetic"
MODELS_DIR = PROJECT_ROOT / "models"

# The 11 fields the API will receive as raw JSON.
FEATURE_COLUMNS = [
    "protocol",
    "service",
    "source_port",
    "destination_port",
    "duration",
    "bytes_sent",
    "bytes_received",
    "packets_sent",
    "packets_received",
    "packet_size",
    "tcp_flags",
]
LABEL_COLUMN = "is_attack"
RANDOM_STATE = 42


def load_data(size: str):
    """Read the raw CSV and return features X and labels y."""
    path = DATA_DIR / f"synthetic_{size}.csv"
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    df = pd.read_csv(path)
    return df[FEATURE_COLUMNS], df[LABEL_COLUMN]


def build_pipeline(X_train: pd.DataFrame, contamination: float, n_estimators: int):
    """Preprocessor + Isolation Forest in one Pipeline."""
    return Pipeline(
        steps=[
            ("preprocessor", build_preprocessor(X_train)),
            (
                "model",
                IsolationForest(
                    n_estimators=n_estimators,
                    contamination=contamination,
                    random_state=RANDOM_STATE,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def evaluate(pipeline: Pipeline, X_test: pd.DataFrame, y_test: pd.Series):
    """Isolation Forest predicts -1 (anomaly) or 1 (normal); map to 1/0."""
    y_pred = (pipeline.predict(X_test) == -1).astype(int)
    # decision_function is HIGHER for normal rows, so negate it for an attack score.
    attack_score = -pipeline.decision_function(X_test)

    print("\n--- Evaluation on held-out test set ---")
    print(f"Precision: {precision_score(y_test, y_pred, zero_division=0):.3f}")
    print(f"Recall:    {recall_score(y_test, y_pred, zero_division=0):.3f}")
    print(f"F1-score:  {f1_score(y_test, y_pred, zero_division=0):.3f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test, attack_score):.3f}")
    print("Confusion matrix (rows = actual, cols = predicted; order 0, 1):")
    print(confusion_matrix(y_test, y_pred))


def main():
    parser = argparse.ArgumentParser(description="Train the BI-Safe anomaly pipeline.")
    parser.add_argument("--size", choices=["small", "medium", "large"], default="small")
    parser.add_argument("--n-estimators", type=int, default=200)
    args = parser.parse_args()

    X, y = load_data(args.size)
    print(f"Loaded {len(X)} rows, attack rate = {y.mean():.3f}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )

    # Contamination = real attack rate in training data, kept inside (0, 0.5].
    contamination = float(min(max(y_train.mean(), 0.001), 0.5))
    print(f"Training on {len(X_train)} rows, contamination = {contamination:.3f}")

    pipeline = build_pipeline(X_train, contamination, args.n_estimators)
    pipeline.fit(X_train)  # unsupervised: labels are NOT used for training

    evaluate(pipeline, X_test, y_test)

    MODELS_DIR.mkdir(exist_ok=True)
    out_path = MODELS_DIR / f"anomaly_pipeline_{args.size}.joblib"
    joblib.dump(pipeline, out_path)
    print(f"\nSaved pipeline to: {out_path}")


if __name__ == "__main__":
    main()