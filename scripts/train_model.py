"""
Model Trainer for BI-Safe
==========================

This script trains an Isolation Forest model on the preprocessed
synthetic network traffic datasets.

It performs the following steps:
1. Loads the preprocessed training data
2. Trains an Isolation Forest model
3. Makes predictions on the testing data
4. Saves the trained model and predictions

Requirements:
    pip install pandas numpy scikit-learn joblib

Run:
    python scripts/train_model.py
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest


# Get the project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")


# Target column
TARGET_COLUMN = "is_attack"

# Default hyperparameters
CONTAMINATION = 0.05
N_ESTIMATORS = 100
RANDOM_STATE = 42


def load_training_data(train_file, test_file):
    """Load preprocessed training and testing data."""
    print(f"Loading {train_file}...")
    train_df = pd.read_csv(train_file)
    test_df = pd.read_csv(test_file)
    print(f"  Train: {len(train_df):,} rows")
    print(f"  Test:  {len(test_df):,} rows")
    return train_df, test_df


def train_model(train_df):
    """Train an Isolation Forest model."""
    X_train = train_df.drop(columns=[TARGET_COLUMN])

    print(f"\nTraining Isolation Forest...")
    print(f"  Contamination: {CONTAMINATION}")
    print(f"  n_estimators:  {N_ESTIMATORS}")

    model = IsolationForest(
        contamination=CONTAMINATION,
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train)
    print(f"  Model trained successfully")
    return model


def make_predictions(model, test_df):
    """Make predictions on the test set."""
    X_test = test_df.drop(columns=[TARGET_COLUMN])

    print(f"\nMaking predictions...")
    predictions = model.predict(X_test)
    scores = model.decision_function(X_test)

    # Isolation Forest returns: 1 = normal, -1 = anomaly
    # Convert to match our labels: 0 = normal, 1 = attack
    predictions = np.where(predictions == -1, 1, 0)

    print(f"  Predictions made: {len(predictions):,}")
    print(f"  Detected anomalies: {predictions.sum():,} ({predictions.mean()*100:.2f}%)")

    return predictions, scores


def save_model(model, model_path):
    """Save the trained model using joblib."""
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    print(f"\n  Model saved to: {model_path}")


def save_predictions(test_df, predictions, scores, output_file):
    """Save predictions and scores to CSV."""
    results = test_df.copy()
    results["prediction"] = predictions
    results["anomaly_score"] = scores
    results.to_csv(output_file, index=False)
    print(f"  Predictions saved to: {output_file}")


def main():
    """Main function to train the model on all datasets."""
    datasets = [
        ("preprocessed_small_train.csv", "preprocessed_small_test.csv",
         "isolation_forest_small.pkl", "predictions_small.csv"),
        ("preprocessed_medium_train.csv", "preprocessed_medium_test.csv",
         "isolation_forest_medium.pkl", "predictions_medium.csv"),
        ("preprocessed_large_train.csv", "preprocessed_large_test.csv",
         "isolation_forest_large.pkl", "predictions_large.csv"),
    ]

    for train_file, test_file, model_file, pred_file in datasets:
        print("\n" + "=" * 60)
        print(f"Training on: {train_file}")
        print("=" * 60)

        train_path = os.path.join(DATA_DIR, train_file)
        test_path = os.path.join(DATA_DIR, test_file)
        model_path = os.path.join(MODEL_DIR, model_file)
        pred_path = os.path.join(DATA_DIR, pred_file)

        if not os.path.exists(train_path) or not os.path.exists(test_path):
            print(f"WARNING: Files not found. Skipping.")
            continue

        train_df, test_df = load_training_data(train_path, test_path)
        model = train_model(train_df)
        predictions, scores = make_predictions(model, test_df)
        save_model(model, model_path)
        save_predictions(test_df, predictions, scores, pred_path)

    print("\n" + "=" * 60)
    print("Model training complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()