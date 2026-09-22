"""
Model Evaluator for BI-Safe
============================

This script evaluates the trained Isolation Forest model by comparing
predictions against ground truth labels.

It performs the following steps:
1. Loads the predictions from Phase 3
2. Calculates precision, recall, F1-score, and accuracy
3. Generates a confusion matrix
4. Saves the evaluation metrics

Requirements:
    pip install pandas numpy scikit-learn matplotlib seaborn

Run:
    python scripts/evaluate_model.py
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
    classification_report,
)


# Get the project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
RESULTS_DIR = os.path.join(BASE_DIR, "results")


# Column names
TARGET_COLUMN = "is_attack"
PREDICTION_COLUMN = "prediction"


def load_predictions(filepath):
    """Load the predictions CSV file."""
    print(f"Loading {filepath}...")
    df = pd.read_csv(filepath)
    print(f"  Loaded {len(df):,} rows")
    return df


def calculate_metrics(y_true, y_pred):
    """Calculate all evaluation metrics."""
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    accuracy = accuracy_score(y_true, y_pred)

    return {
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "accuracy": accuracy,
    }


def plot_confusion_matrix(y_true, y_pred, output_file, dataset_name):
    """Plot and save the confusion matrix as a heatmap."""
    cm = confusion_matrix(y_true, y_pred)

    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Normal", "Attack"],
        yticklabels=["Normal", "Attack"],
    )
    plt.title(f"Confusion Matrix - {dataset_name}")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(output_file, dpi=150)
    plt.close()
    print(f"  Confusion matrix saved to: {output_file}")


def evaluate_dataset(predictions_file, dataset_name):
    """Evaluate one dataset and return metrics."""
    print("\n" + "=" * 60)
    print(f"Evaluating: {dataset_name}")
    print("=" * 60)

    df = load_predictions(predictions_file)

    if TARGET_COLUMN not in df.columns or PREDICTION_COLUMN not in df.columns:
        print(f"  ERROR: Missing required columns.")
        return None

    y_true = df[TARGET_COLUMN].values
    y_pred = df[PREDICTION_COLUMN].values

    # Calculate metrics
    metrics = calculate_metrics(y_true, y_pred)

    print(f"\n  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1-Score:  {metrics['f1_score']:.4f}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")

    # Classification report
    print(f"\n  Classification Report:")
    print(classification_report(y_true, y_pred, target_names=["Normal", "Attack"], zero_division=0))

    # Confusion matrix
    cm_file = os.path.join(RESULTS_DIR, f"confusion_matrix_{dataset_name}.png")
    plot_confusion_matrix(y_true, y_pred, cm_file, dataset_name)

    return {
        "dataset": dataset_name,
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1_score": metrics["f1_score"],
        "accuracy": metrics["accuracy"],
    }


def save_summary(results):
    """Save the summary table as CSV."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    df = pd.DataFrame(results)
    output_file = os.path.join(RESULTS_DIR, "evaluation_summary.csv")
    df.to_csv(output_file, index=False)
    print(f"\n  Summary saved to: {output_file}")
    print("\n  Summary table:")
    print(df.to_string(index=False))


def main():
    """Main function to evaluate all datasets."""
    datasets = [
        ("predictions_small.csv", "small"),
        ("predictions_medium.csv", "medium"),
        ("predictions_large.csv", "large"),
    ]

    results = []

    for pred_file, dataset_name in datasets:
        pred_path = os.path.join(DATA_DIR, pred_file)

        if not os.path.exists(pred_path):
            print(f"WARNING: {pred_path} not found. Skipping.")
            continue

        result = evaluate_dataset(pred_path, dataset_name)
        if result:
            results.append(result)

    if results:
        save_summary(results)

    print("\n" + "=" * 60)
    print("Evaluation complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()