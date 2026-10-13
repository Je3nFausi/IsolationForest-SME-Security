# Continuous Security Monitoring for Kenyan SMEs

## Project Summary

BI-Safe is a continuous security monitoring system that uses the Isolation Forest algorithm for anomaly detection on network traffic data. The system is designed to help Kenyan small and medium enterprises (SMEs) improve their data security behaviour through real-time alerts and visual feedback. The system uses a real-time data pipeline with a producer-consumer architecture, streaming simulated network traffic through Kafka for real-time anomaly detection.

## Problem Statement

80% of Kenyan SMEs lack basic security measures. Existing solutions are either too expensive (e.g., SecureGBO at Sh16,500) or lack real-time anomaly detection. This project addresses these gaps by providing a free, accessible, and behaviour-focused security solution.

## Objectives

1. To identify security behaviour patterns and threat vectors prevalent among Kenyan SMEs
2. To review existing real-time intrusion detection machine learning algorithms for anomaly detection
3. To design a continuous monitoring architecture with real-time data collection, anomaly detection, alerting, and behaviour tracking
4. To develop the system using Python for anomaly detection and a web-based dashboard for visualisation
5. To evaluate the system through testing and user acceptance assessment

## Datasets

The system uses a combination of synthetic and publicly available network traffic data:

### Synthetic Data (Primary for Development)
Synthetic datasets are generated using Python libraries (Faker, NumPy) to simulate realistic network traffic patterns with multiple attack types. Three datasets are generated:
- `synthetic_small.csv` - 5,000 events, 10% anomaly rate, 4 attack types
- `synthetic_medium.csv` - 20,000 events, 5% anomaly rate, 8 attack types
- `synthetic_large.csv` - 100,000 events, 2% anomaly rate, 12 attack types

### Publicly Available Data (Supplementary)
- CIC-IDS-2017 - 2.8 million rows, 79 features (modern attack types)
- UNSW-NB15 - 2.5 million rows, 49 features (9 attack families)
- NSL-KDD - 125,000 rows, 41 features (benchmark dataset)

## How to Generate Data

The datasets are not included in this repository due to size. To regenerate them:

1. Run `python scripts/generate_synthetic_data.py`
2. Run `python scripts/preprocess.py`
3. Run `python scripts/train_model.py`

For real datasets, download from:
- CIC-IDS-2017: https://www.kaggle.com/datasets/cicdataset/cicids2017

## Technologies Used

- **Python 3.9+** - Primary programming language for model development
- **Scikit-learn** - Isolation Forest algorithm and evaluation metrics
- **Pandas & NumPy** - Data processing and numerical computing
- **Apache Kafka** - Message broker for real-time data streaming
- **Flask** - Web framework for building the dashboard
- **HTML, CSS, JavaScript** - Frontend for the web dashboard
- **Chart.js** - Data visualisation library for charts
- **SQLite** - Database for storing predictions, alerts, and feedback
- **Twilio API** - SMS and WhatsApp alerts
- **Draw.io** - Drawing design diagrams

## System Architecture

The system follows a producer-consumer architecture:
Producer → Kafka Broker → Consumer (Isolation Forest) → Database → Trigger → Web Dashboard


- **Producer**: Simulates network traffic by streaming data from CSV files
- **Kafka Broker**: Decouples the producer from the consumer
- **Consumer**: Runs the Isolation Forest model for real-time anomaly detection
- **Database**: Stores predictions, alerts, and feedback
- **Trigger**: Checks for anomalies and generates alerts
- **Web Dashboard**: Displays security trends, alerts, and recommendations
- **Admin UI**: Controls the producer and monitors model drift

## Actors

- **SME Owner**: Receives alerts, views the dashboard, provides feedback on model performance
- **System Administrator**: Controls the producer, monitors model drift, retrains and redeploys the model

## Repository Structure
continuous-security-monitoring-system/
├── README.md # Project overview
├── requirements.txt # Python dependencies
├── data/ # Datasets
│ ├── synthetic_small.csv
│ ├── synthetic_medium.csv
│ └── synthetic_large.csv
├── notebooks/ # Jupyter notebooks for development
│ ├── 01_data_preparation.ipynb
│ ├── 02_model_training.ipynb
│ └── 03_evaluation.ipynb
├── scripts/ # Python scripts
│ ├── generate_synthetic_data.py
│ ├── preprocess.py
│ ├── train_model.py
│ ├── evaluate_model.py
│ ├── producer.py
│ ├── consumer.py
│ └── alert_trigger.py
├── app/ # Flask web dashboard
│ ├── app.py
│ ├── templates/
│ └── static/
├── models/ # Trained model files
│ └── isolation_forest.pkl
├── database/ # SQLite database
│ └── continuouse-security-monitoring-system.db
├── results/ # Output CSV files and metrics
├── diagrams/ # Design diagrams (Chapter 4)
└── tests/ # Unit tests

## Pipeline Architecture (v2)

BI-Safe now serves a fitted scikit-learn `Pipeline` through a REST API. The caller sends raw JSON and gets a prediction back, with no manual preprocessing. The original flow (`producer.py`, `consumer.py`, `isolation_forest_*.pkl`) is unchanged.

### How it works

```
data/synthetic/*.csv --> producer_raw.py --> Kafka topic "network-traffic-raw"
        --> consumer_api.py --> POST to API --> Pipeline (preprocess + Isolation Forest)
        --> predictions table (SQLite) --> alert_to_db.py --> alerts table --> dashboard
```

The Pipeline has two steps: a `ColumnTransformer` (median imputation and standard scaling for numeric fields, most-frequent imputation and one-hot encoding for categorical fields) followed by `IsolationForest`. Training uses no labels. `is_attack` is only used for evaluation.

### New files

| Path | Purpose |
|---|---|
| `ml_pipeline/preprocessing.py` | Builds the `ColumnTransformer` |
| `ml_pipeline/train_anomaly_pipeline.py` | Trains, evaluates and saves the Pipeline |
| `models/anomaly_pipeline_{small,medium,large}.joblib` | Fitted Pipelines |
| `api/anomaly_api.py` | Flask API serving the Pipeline |
| `scripts/producer_raw.py` | Streams raw events to `network-traffic-raw` |
| `scripts/consumer_api.py` | Reads the topic, calls the API, saves predictions |
| `scripts/alert_to_db.py` | Writes alerts to the database for the dashboard |
| `requirements/` | `base.txt`, `dev.txt`, `prod.txt`, `constraints.txt` |

### API input fields

`protocol`, `service`, `source_port`, `destination_port`, `duration`, `bytes_sent`, `bytes_received`, `packets_sent`, `packets_received`, `packet_size`, `tcp_flags`. Only `tcp_flags` may be missing (it is imputed). Extra fields are ignored.

### Ports

| Service | Port |
|---|---|
| Dashboard (`app/app.py`) | 5001 |
| Anomaly API (`api/anomaly_api.py`) | 5002 |
| Kafka | 9092 |

### Install

```bash
pip install -r requirements/base.txt -c requirements/constraints.txt
```

The Pipelines were trained with scikit-learn 1.9.1. Load them with the same version.

### Train

```bash
python -m ml_pipeline.train_anomaly_pipeline --size small
python -m ml_pipeline.train_anomaly_pipeline --size medium
python -m ml_pipeline.train_anomaly_pipeline --size large
```

Held-out test results (stratified 80/20 split of the raw synthetic data):

| Size | Attack rate | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| small | 10% | 0.663 | 0.670 | 0.667 | 0.922 |
| medium | 5% | 0.462 | 0.515 | 0.487 | 0.859 |
| large | 2% | 0.323 | 0.320 | 0.322 | 0.868 |

Precision and recall fall as attacks get rarer, while ROC-AUC stays high.

### Run the full flow

Start Kafka first. Then, in separate terminals, from the project root:

```bash
python -m api.anomaly_api                  # 1. API (port 5002)
python scripts/consumer_api.py             # 2. consumer (start before the producer)
python scripts/producer_raw.py             # 3. producer
python scripts/alert_to_db.py              # 4. after the consumer finishes
python app/app.py                          # 5. dashboard on http://127.0.0.1:5001
```

Use `BISAFE_MODEL_SIZE=medium` before the API command to serve a different Pipeline (default `small`). Dry runs that need no Kafka: `python scripts/producer_raw.py --dry-run` and `python scripts/consumer_api.py --dry-run` (the API must be running for the second).

Check the API directly:

```bash
curl http://127.0.0.1:5002/health
```

End-to-end check on the first 1,000 small events: recall 0.68, precision 0.71, 31 false alarms out of 889 normal events, matching the offline evaluation.

### Score and alert conventions

- The API returns `anomaly_score` where higher means more anomalous.
- `consumer_api.py` flips the sign before saving, so the database keeps the original meaning: higher means more normal, and anomalies are negative.
- Alert priority (`alert_to_db.py`): HIGH below -0.05, MEDIUM below -0.03, otherwise LOW.
- These thresholds were calibrated on the small dataset (106 flagged events, scores from -0.066 to -0.0001). Re-check them for medium and large. On the same data, the old thresholds (-0.05 and -0.15) gave almost only LOW alerts.

### Known limitations

- Only the small dataset has been run through the full Kafka, API and database flow. The medium and large Pipelines are trained and saved but not yet wired in.
- `alert_trigger.py` still reads `consumer_results.csv` and writes a JSON log. It does not write to the database. `alert_to_db.py` does.
- The dashboard's own producer and retrain controls still use the original flow.
- The `alerts` table's `timestamp`, `sme_id` and `prediction_id` columns are not filled.

### Threshold check on the medium dataset

The alert thresholds (HIGH below -0.05, MEDIUM below -0.03) were calibrated on the small dataset and then applied, unchanged, to the first 1,000 events of the medium dataset (served by the medium Pipeline). 55 events were flagged: 4 HIGH, 9 MEDIUM and 42 LOW. All 13 HIGH and MEDIUM alerts were true attacks, against 43% of LOW alerts (66% on the small dataset). End-to-end recall was 0.58 and precision 0.56 (offline: 0.515 and 0.462). These are small samples, so the results are indicative only. The large dataset has not been tested.