"""
Data Preprocessor for BI-Safe
==============================

This script preprocesses the synthetic network traffic datasets for training
an Isolation Forest anomaly detection model.

It performs the following steps:
1. Loads the CSV files
2. Removes duplicate rows
3. Handles missing values
4. Drops non-numerical columns
5. Normalises numerical features using StandardScaler
6. Splits each dataset into training (80%) and testing (20%)
7. Saves the preprocessed data as CSV files

Requirements:
    pip install pandas numpy scikit-learn

Run:
    python scripts/preprocess.py
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


# Get the project root directory (one level up from scripts/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


# Columns that should be dropped (non-numerical, not useful for training)
DROP_COLUMNS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "service",
    "tcp_flags",
    "attack_type",       # <-- ADDED: this is a label, not a feature
]

# Target column
TARGET_COLUMN = "is_attack"


def load_dataset(filepath):
    """Load a CSV file into a pandas DataFrame."""
    print(f"Loading {filepath}...")
    df = pd.read_csv(filepath)
    print(f"  Loaded {len(df):,} rows and {len(df.columns)} columns")
    return df


def remove_duplicates(df):
    """Remove duplicate rows from the DataFrame."""
    before = len(df)
    df = df.drop_duplicates()
    after = len(df)
    removed = before - after
    if removed > 0:
        print(f"  Removed {removed:,} duplicate rows")
    return df


def handle_missing_values(df):
    """Handle missing values by filling numerical columns with the mean."""
    missing = df.isnull().sum().sum()
    if missing > 0:
        print(f"  Found {missing:,} missing values. Filling with column means...")
        for col in df.select_dtypes(include=[np.number]).columns:
            df[col] = df[col].fillna(df[col].mean())
        df = df.dropna()
    else:
        print("  No missing values found")
    return df


def drop_non_numerical(df):
    """Drop non-numerical columns that cannot be used for training."""
    columns_to_drop = [col for col in DROP_COLUMNS if col in df.columns]
    df = df.drop(columns=columns_to_drop)
    print(f"  Dropped {len(columns_to_drop)} non-numerical columns")
    return df


def normalise_features(df):
    """Normalise numerical features using StandardScaler."""
    # Separate features and target
    X = df.drop(columns=[TARGET_COLUMN])
    y = df[TARGET_COLUMN]

    # Keep only numerical columns (safety check)
    X = X.select_dtypes(include=[np.number])

    # Fit scaler and transform features
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(
        scaler.fit_transform(X),
        columns=X.columns,
        index=X.index
    )

    # Combine back with target
    df_scaled = pd.concat([X_scaled, y], axis=1)
    print(f"  Normalised {len(X.columns)} features (mean ~0, std ~1)")
    return df_scaled


def split_data(df, test_size=0.2, random_state=42):
    """Split the DataFrame into training and testing sets."""
    X = df.drop(columns=[TARGET_COLUMN])
    y = df[TARGET_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )

    # Recombine for saving
    train_df = pd.concat([X_train, y_train], axis=1)
    test_df = pd.concat([X_test, y_test], axis=1)

    print(f"  Training set: {len(train_df):,} rows")
    print(f"  Testing set:  {len(test_df):,} rows")
    print(f"  Attack rate (train): {y_train.mean()*100:.2f}%")
    print(f"  Attack rate (test):  {y_test.mean()*100:.2f}%")

    return train_df, test_df


def preprocess_dataset(input_file, output_prefix, output_dir):
    """Run the full preprocessing pipeline for one dataset."""
    print("\n" + "=" * 60)
    print(f"Preprocessing: {input_file}")
    print("=" * 60)

    df = load_dataset(input_file)
    df = remove_duplicates(df)
    df = handle_missing_values(df)
    df = drop_non_numerical(df)
    df = normalise_features(df)
    train_df, test_df = split_data(df)

    os.makedirs(output_dir, exist_ok=True)
    train_path = os.path.join(output_dir, f"{output_prefix}_train.csv")
    test_path = os.path.join(output_dir, f"{output_prefix}_test.csv")

    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)

    print(f"  Saved: {train_path}")
    print(f"  Saved: {test_path}")

    return train_df, test_df


def main():
    """Main function to run the preprocessing pipeline for all datasets."""
    datasets = [
        ("synthetic/synthetic_small.csv", "preprocessed_small"),
        ("synthetic/synthetic_medium.csv", "preprocessed_medium"),
        ("synthetic/synthetic_large.csv", "preprocessed_large"),
    ]

    for filename, output_prefix in datasets:
        input_file = os.path.join(DATA_DIR, filename)
        if os.path.exists(input_file):
            preprocess_dataset(input_file, output_prefix, DATA_DIR)
        else:
            print(f"WARNING: {input_file} not found. Skipping.")

    print("\n" + "=" * 60)
    print("Preprocessing complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()