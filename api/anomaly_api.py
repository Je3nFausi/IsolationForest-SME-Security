"""
BI-Safe anomaly detection API.

Run from the project root:
    python -m api.anomaly_api

Serves a fitted scikit-learn Pipeline. The caller sends RAW JSON and
gets predictions back; all preprocessing happens inside the Pipeline.
"""

import os
from pathlib import Path

import joblib
import pandas as pd
from flask import Flask, jsonify, request

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_SIZE = os.environ.get("BISAFE_MODEL_SIZE", "small")
MODEL_PATH = PROJECT_ROOT / "models" / f"anomaly_pipeline_{MODEL_SIZE}.joblib"

# Must match FEATURE_COLUMNS in ml_pipeline/train_anomaly_pipeline.py
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

app = Flask(__name__)
pipeline = joblib.load(MODEL_PATH)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "model": MODEL_PATH.name})


@app.post("/api/v1/models/anomaly-detector/predictions")
def predict():
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Request body must be valid JSON."}), 400

    # Accept one event (an object) or many events (a list of objects).
    events = [payload] if isinstance(payload, dict) else payload
    if not isinstance(events, list) or not events or not all(
        isinstance(e, dict) for e in events
    ):
        return jsonify({"error": "Send a JSON object or a non-empty list of objects."}), 400

    df = pd.DataFrame(events)

    # tcp_flags may legitimately be missing (the pipeline imputes it).
    # Every other feature must be present.
    required = [c for c in FEATURE_COLUMNS if c != "tcp_flags"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        return jsonify({"error": f"Missing required fields: {missing}"}), 400
    if "tcp_flags" not in df.columns:
        df["tcp_flags"] = None

    df = df[FEATURE_COLUMNS]

    try:
        labels = pipeline.predict(df)              # -1 = anomaly, 1 = normal
        scores = -pipeline.decision_function(df)   # higher = more anomalous
    except Exception as exc:
        return jsonify({"error": f"Could not score input: {exc}"}), 422

    predictions = [
        {
            "is_anomaly": bool(label == -1),
            "anomaly_score": round(float(score), 4),
        }
        for label, score in zip(labels, scores)
    ]
    return jsonify({"model": MODEL_PATH.name, "predictions": predictions})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)