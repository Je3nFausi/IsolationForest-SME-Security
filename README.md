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
