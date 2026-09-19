"""
CAN-Sentinel - Rule-Based Detection Module

Detects suspicious CAN traffic using frequency, timing,
payload, and repeated-message rules.
"""

import os

import pandas as pd


# Project paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FEATURE_FILE = os.path.join(
    BASE_DIR,
    "models",
    "extracted_features.csv"
)

ML_RESULT_FILE = os.path.join(
    BASE_DIR,
    "models",
    "detection_results.csv"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "models",
    "rule_detection_results.csv"
)


# CAN traffic thresholds
FREQUENCY_THRESHOLD = 15
MIN_INTERVAL_THRESHOLD = 0.05
PAYLOAD_MAX_THRESHOLD = 250
REPEATED_MESSAGE_THRESHOLD = 1


# ------------------------------------------------------------
# Data loading
# ------------------------------------------------------------

def load_data():
    """Load extracted features and ML results."""

    if not os.path.exists(FEATURE_FILE):
        print(f"Feature file not found: {FEATURE_FILE}")
        return pd.DataFrame()

    try:
        data = pd.read_csv(FEATURE_FILE)

        if os.path.exists(ML_RESULT_FILE):
            ml_data = pd.read_csv(ML_RESULT_FILE)

            ml_columns = [
                "ml_prediction",
                "anomaly_score",
                "ml_anomaly",
                "status"
            ]

            available_columns = [
                column
                for column in ml_columns
                if column in ml_data.columns
            ]

            if available_columns:
                data = pd.concat(
                    [
                        data.reset_index(drop=True),
                        ml_data[available_columns].reset_index(drop=True)
                    ],
                    axis=1
                )

        return data

    except Exception as error:
        print(f"Error loading detection data: {error}")
        return pd.DataFrame()


# ------------------------------------------------------------
# Rule checks
# ------------------------------------------------------------

def check_frequency(row):
    """Detect unusually frequent CAN messages."""

    return int(
        row["message_frequency"] > FREQUENCY_THRESHOLD
    )


def check_timing(row):
    """Detect unusually short message intervals."""

    interval = row["time_interval"]

    return int(
        interval > 0
        and interval < MIN_INTERVAL_THRESHOLD
    )


def check_payload(row):
    """Detect suspiciously high payload values."""

    return int(
        row["payload_max"] >= PAYLOAD_MAX_THRESHOLD
    )


def check_repeated_message(row):
    """Detect repeated CAN messages."""

    return int(
        row["repeated_message"] >= REPEATED_MESSAGE_THRESHOLD
    )


# ------------------------------------------------------------
# Rule detection
# ------------------------------------------------------------

def apply_rules(data):
    """Apply all rule-based checks to CAN traffic."""

    result = data.copy()

    result["rule_frequency"] = result.apply(
        check_frequency,
        axis=1
    )

    result["rule_timing"] = result.apply(
        check_timing,
        axis=1
    )

    result["rule_payload"] = result.apply(
        check_payload,
        axis=1
    )

    result["rule_repetition"] = result.apply(
        check_repeated_message,
        axis=1
    )

    rule_columns = [
        "rule_frequency",
        "rule_timing",
        "rule_payload",
        "rule_repetition"
    ]

    result["rule_score"] = result[
        rule_columns
    ].sum(axis=1)

    result["rule_anomaly"] = (
        result["rule_score"] > 0
    ).astype(int)

    result["rule_status"] = result[
        "rule_anomaly"
    ].map(
        {
            0: "Normal",
            1: "Suspicious"
        }
    )

    return result


# ------------------------------------------------------------
# Combined detection
# ------------------------------------------------------------

def combine_detection_results(data):
    """
    Combine rule-based detection with ML detection.

    A frame is considered suspicious when either
    the rules or Isolation Forest identifies it.
    """

    result = data.copy()

    if "ml_anomaly" not in result.columns:
        result["ml_anomaly"] = 0

    result["combined_anomaly"] = (
        (
            result["rule_anomaly"] == 1
        )
        |
        (
            result["ml_anomaly"] == 1
        )
    ).astype(int)

    result["detection_status"] = result[
        "combined_anomaly"
    ].map(
        {
            0: "Normal",
            1: "Suspicious"
        }
    )

    return result


# ------------------------------------------------------------
# Save results
# ------------------------------------------------------------

def save_results(data):
    """Save rule and combined detection results."""

    try:
        data.to_csv(
            OUTPUT_FILE,
            index=False
        )

        print(f"Rule detection results saved: {OUTPUT_FILE}")

    except Exception as error:
        print(
            f"Error saving rule detection results: "
            f"{error}"
        )


# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

def print_summary(data):
    """Display rule detection summary."""

    total = len(data)

    rule_anomalies = int(
        data["rule_anomaly"].sum()
    )

    combined_anomalies = int(
        data["combined_anomaly"].sum()
    )

    print()
    print("=" * 60)
    print("Rule-Based Detection Summary")
    print("=" * 60)

    print(f"Total records             : {total}")
    print(f"Rule-based suspicious     : {rule_anomalies}")
    print(f"Combined suspicious       : {combined_anomalies}")

    print()
    print("Rule triggers:")

    print(
        f"- Frequency anomalies     : "
        f"{data['rule_frequency'].sum()}"
    )

    print(
        f"- Timing anomalies        : "
        f"{data['rule_timing'].sum()}"
    )

    print(
        f"- Payload anomalies       : "
        f"{data['rule_payload'].sum()}"
    )

    print(
        f"- Repeated messages       : "
        f"{data['rule_repetition'].sum()}"
    )


# ------------------------------------------------------------
# Main process
# ------------------------------------------------------------

def main():
    """Run the complete rule-based detection process."""

    print()
    print("=" * 60)
    print("CAN-Sentinel Rule Detector")
    print("=" * 60)

    data = load_data()

    if data.empty:
        print("ERROR: No detection data available.")
        return

    required_columns = [
        "message_frequency",
        "time_interval",
        "payload_max",
        "repeated_message"
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in data.columns
    ]

    if missing_columns:
        print(
            "ERROR: Missing required feature columns:"
        )

        for column in missing_columns:
            print(f"- {column}")

        return

    data = apply_rules(data)

    data = combine_detection_results(data)

    save_results(data)

    print_summary(data)

    print()
    print("=" * 60)
    print("Rule detection completed successfully.")
    print("=" * 60)


# ------------------------------------------------------------
# Program entry point
# ------------------------------------------------------------

if __name__ == "__main__":
    main()