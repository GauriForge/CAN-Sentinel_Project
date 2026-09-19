"""
CAN-Sentinel - Threat Severity Module

Assigns Low, Medium, High, or Critical severity
to suspicious CAN traffic using rule and ML evidence.
"""

import os

import pandas as pd


# Project paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_FILE = os.path.join(
    BASE_DIR,
    "models",
    "rule_detection_results.csv"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "models",
    "threat_severity_results.csv"
)


# Severity thresholds
HIGH_RULE_SCORE = 2
CRITICAL_RULE_SCORE = 3
HIGH_FREQUENCY = 30
CRITICAL_FREQUENCY = 50


# ------------------------------------------------------------
# Data loading
# ------------------------------------------------------------

def load_detection_results():
    """Load combined detection results."""

    if not os.path.exists(INPUT_FILE):
        print(f"Detection file not found: {INPUT_FILE}")
        return pd.DataFrame()

    try:
        data = pd.read_csv(INPUT_FILE)

        print(f"Loaded {len(data)} detection records.")

        return data

    except Exception as error:
        print(f"Error loading detection results: {error}")
        return pd.DataFrame()


# ------------------------------------------------------------
# Severity calculation
# ------------------------------------------------------------

def calculate_severity(row):
    """Calculate the threat severity for one CAN frame."""

    rule_score = int(
        row.get("rule_score", 0)
    )

    ml_anomaly = int(
        row.get("ml_anomaly", 0)
    )

    frequency = float(
        row.get("message_frequency", 0)
    )

    payload_rule = int(
        row.get("rule_payload", 0)
    )

    timing_rule = int(
        row.get("rule_timing", 0)
    )

    combined_anomaly = int(
        row.get("combined_anomaly", 0)
    )

    if combined_anomaly == 0:
        return "Low"

    if (
        rule_score >= CRITICAL_RULE_SCORE
        or frequency >= CRITICAL_FREQUENCY
    ):
        return "Critical"

    if (
        rule_score >= HIGH_RULE_SCORE
        or frequency >= HIGH_FREQUENCY
        or (
            ml_anomaly == 1
            and payload_rule == 1
        )
    ):
        return "High"

    if (
        rule_score >= 1
        or timing_rule == 1
        or ml_anomaly == 1
    ):
        return "Medium"

    return "Low"


# ------------------------------------------------------------
# Severity reason
# ------------------------------------------------------------

def generate_reason(row):
    """Generate a short explanation for the severity."""

    reasons = []

    if row.get("rule_frequency", 0) == 1:
        reasons.append("high message frequency")

    if row.get("rule_timing", 0) == 1:
        reasons.append("short message interval")

    if row.get("rule_payload", 0) == 1:
        reasons.append("suspicious payload")

    if row.get("rule_repetition", 0) == 1:
        reasons.append("repeated message")

    if row.get("ml_anomaly", 0) == 1:
        reasons.append("ML anomaly")

    if not reasons:
        return "No significant threat detected"

    return ", ".join(reasons)


# ------------------------------------------------------------
# Apply severity
# ------------------------------------------------------------

def assign_severity(data):
    """Assign severity and reason to each CAN frame."""

    result = data.copy()

    result["severity"] = result.apply(
        calculate_severity,
        axis=1
    )

    result["severity_reason"] = result.apply(
        generate_reason,
        axis=1
    )

    return result


# ------------------------------------------------------------
# Save results
# ------------------------------------------------------------

def save_results(data):
    """Save severity analysis results."""

    try:
        data.to_csv(
            OUTPUT_FILE,
            index=False
        )

        print(f"Severity results saved: {OUTPUT_FILE}")

    except Exception as error:
        print(
            f"Error saving severity results: "
            f"{error}"
        )


# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

def print_summary(data):
    """Display severity summary."""

    print()
    print("=" * 60)
    print("Threat Severity Summary")
    print("=" * 60)

    for level in [
        "Low",
        "Medium",
        "High",
        "Critical"
    ]:
        count = int(
            (data["severity"] == level).sum()
        )

        print(
            f"{level:<10}: {count}"
        )


# ------------------------------------------------------------
# Main process
# ------------------------------------------------------------

def main():
    """Run the complete threat severity process."""

    print()
    print("=" * 60)
    print("CAN-Sentinel Threat Severity")
    print("=" * 60)

    data = load_detection_results()

    if data.empty:
        print("ERROR: No detection results available.")
        return

    required_columns = [
        "rule_score",
        "combined_anomaly",
        "message_frequency"
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in data.columns
    ]

    if missing_columns:
        print("ERROR: Missing required columns:")

        for column in missing_columns:
            print(f"- {column}")

        return

    data = assign_severity(data)

    save_results(data)

    print_summary(data)

    print()
    print("=" * 60)
    print("Threat severity analysis completed successfully.")
    print("=" * 60)


# ------------------------------------------------------------
# Program entry point
# ------------------------------------------------------------

if __name__ == "__main__":
    main()