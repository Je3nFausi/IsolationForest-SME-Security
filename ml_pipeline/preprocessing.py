"""
Preprocessing for the BI-Safe anomaly pipeline.

build_preprocessor() returns an UNFITTED ColumnTransformer. It is fitted
later, inside the Pipeline, in train_anomaly_pipeline.py.
"""

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


def get_feature_types(X: pd.DataFrame):
    """Numeric columns by dtype; every other column is treated as categorical."""
    numeric_features = X.select_dtypes(include="number").columns.tolist()
    categorical_features = [c for c in X.columns if c not in numeric_features]
    return numeric_features, categorical_features


def build_preprocessor(X: pd.DataFrame) -> ColumnTransformer:
    """Build the ColumnTransformer: impute + scale numeric, impute + encode categorical."""
    numeric_features, categorical_features = get_feature_types(X)

    numeric_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )

    categorical_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            (
                "encoder",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
            ),
        ]
    )

    transformers = []
    if numeric_features:
        transformers.append(("num", numeric_pipeline, numeric_features))
    if categorical_features:
        transformers.append(("cat", categorical_pipeline, categorical_features))

    return ColumnTransformer(transformers=transformers, remainder="drop")