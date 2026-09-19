"""
CAN-Sentinel - Anomaly Detection Module

Uses Isolation Forest to detect anomalous CAN traffic
from the extracted feature dataset.
"""

import os
import pickle

import pandas as pd
from sklearn.ensemble import IsolationForest


# Project paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FEATURE_FILE = os.path.join(
    BASE_DIR,
    "models",
    "extracted_features.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "anomaly_model.pkl"
)

RESULT_FILE = os.path.join(
    MODEL_DIR,
    "detection_results.csv"
)


# Features not used directly for ML
NON_FEATURE_COLUMNS = [
    "timestamp",
    "label"
]


# ------------------------------------------------------------
# Data loading
# ------------------------------------------------------------

def load_features():
    """Load extracted CAN features."""

    if not os.path.exists(FEATURE_FILE):
        print(f"Feature file not found: {FEATURE_FILE}")
        return pd.DataFrame()

    try:
        data = pd.read_csv(FEATURE_FILE)

        print(f"Loaded {len(data)} feature records.")

        return data

    except Exception as error:
        print(f"Error loading feature dataset: {error}")
        return pd.DataFrame()


# ------------------------------------------------------------
# Feature preparation
# ------------------------------------------------------------

def prepare_features(data):
    """Prepare numerical features for Isolation Forest."""

    feature_data = data.drop(
        columns=NON_FEATURE_COLUMNS,
        errors="ignore"
    )

    feature_data = feature_data.select_dtypes(
        include=["number"]
    )

    feature_data = feature_data.replace(
        [float("inf"), float("-inf")],
        0
    )

    feature_data = feature_data.fillna(0)

    return feature_data


# ------------------------------------------------------------
# Model training
# ------------------------------------------------------------

def train_model(feature_data, labels):
    """
    Train Isolation Forest using normal CAN traffic.

    The model learns the normal traffic pattern and
    identifies deviations as anomalies.
    """

    normal_data = feature_data[labels == 0]

    if normal_data.empty:
        print("No normal traffic available for training.")
        return None

    print(
        f"Training Isolation Forest with "
        f"{len(normal_data)} normal records..."
    )

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1
    )

    model.fit(normal_data)

    return model


# ------------------------------------------------------------
# Save model
# ------------------------------------------------------------

def save_model(model):
    """Save the trained anomaly detection model."""

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    try:
        with open(MODEL_FILE, "wb") as file:
            pickle.dump(model, file)

        print(f"Model saved: {MODEL_FILE}")

    except Exception as error:
        print(f"Error saving model: {error}")


# ------------------------------------------------------------
# Detect anomalies
# ------------------------------------------------------------

def detect_anomalies(model, feature_data):
    """Run anomaly detection on CAN traffic."""

    predictions = model.predict(feature_data)
    scores = model.decision_function(feature_data)

    results = pd.DataFrame()

    results["ml_prediction"] = predictions
    results["anomaly_score"] = -scores

    results["ml_anomaly"] = (
        predictions == -1
    ).astype(int)

    results["status"] = results["ml_anomaly"].map(
        {
            0: "Normal",
            1: "Suspicious"
        }
    )

    return results


# ------------------------------------------------------------
# Save detection results
# ------------------------------------------------------------

def save_results(data, detection_results):
    """Save CAN traffic with ML detection results."""

    output = data.copy()

    output["ml_prediction"] = (
        detection_results["ml_prediction"]
    )

    output["anomaly_score"] = (
        detection_results["anomaly_score"]
    )

    output["ml_anomaly"] = (
        detection_results["ml_anomaly"]
    )

    output["status"] = (
        detection_results["status"]
    )

    try:
        output.to_csv(
            RESULT_FILE,
            index=False
        )

        print(f"Detection results saved: {RESULT_FILE}")

    except Exception as error:
        print(
            f"Error saving detection results: "
            f"{error}"
        )


# ------------------------------------------------------------
# Detection summary
# ------------------------------------------------------------

def print_summary(results):
    """Display anomaly detection summary."""

    total = len(results)

    anomalies = int(
        results["ml_anomaly"].sum()
    )

    normal = total - anomalies

    print()
    print("=" * 60)
    print("Anomaly Detection Summary")
    print("=" * 60)

    print(f"Total records       : {total}")
    print(f"Normal records      : {normal}")
    print(f"Anomalous records   : {anomalies}")

    if total > 0:
        percentage = (anomalies / total) * 100
        print(
            f"Anomaly percentage  : "
            f"{percentage:.2f}%"
        )


# ------------------------------------------------------------
# Main process
# ------------------------------------------------------------

def main():
    """Run the complete anomaly detection process."""

    print()
    print("=" * 60)
    print("CAN-Sentinel Anomaly Detector")
    print("=" * 60)

    data = load_features()

    if data.empty:
        print("ERROR: No feature data available.")
        return

    if "label" not in data.columns:
        print("ERROR: Label column is missing.")
        return

    feature_data = prepare_features(data)

    if feature_data.empty:
        print("ERROR: No numerical features available.")
        return

    labels = pd.to_numeric(
        data["label"],
        errors="coerce"
    ).fillna(0)

    model = train_model(
        feature_data,
        labels
    )

    if model is None:
        return

    save_model(model)

    print("\nRunning anomaly detection...")

    detection_results = detect_anomalies(
        model,
        feature_data
    )

    save_results(
        data,
        detection_results
    )

    print_summary(
        detection_results
    )

    print()
    print("=" * 60)
    print("Anomaly detection completed successfully.")
    print("=" * 60)


# ------------------------------------------------------------
# Program entry point
# ------------------------------------------------------------

if __name__ == "__main__":
    main()