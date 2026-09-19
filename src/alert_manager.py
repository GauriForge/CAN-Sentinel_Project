"""
CAN-Sentinel - Alert Manager

Generates and manages security alerts from
threat severity detection results.
"""

import os
from datetime import datetime

import pandas as pd


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

INPUT_FILE = os.path.join(
    BASE_DIR,
    "models",
    "threat_severity_results.csv"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "models",
    "security_alerts.csv"
)


# ============================================================
# ALERT SETTINGS
# ============================================================

ALERT_LEVELS = {
    "Medium": "WARNING",
    "High": "HIGH ALERT",
    "Critical": "CRITICAL ALERT"
}


# ============================================================
# LOAD RESULTS
# ============================================================

def load_results():
    """Load threat severity results."""

    if not os.path.exists(INPUT_FILE):
        print(
            f"Detection results not found: {INPUT_FILE}"
        )
        return pd.DataFrame()

    try:
        return pd.read_csv(INPUT_FILE)

    except Exception as error:
        print(
            f"Error loading detection results: {error}"
        )
        return pd.DataFrame()


# ============================================================
# CAN ID FORMAT
# ============================================================

def format_can_id(value):
    """Convert CAN ID to standard hexadecimal format."""

    try:
        text = str(value).strip()

        if text.lower().startswith("0x"):
            number = int(text, 16)
        else:
            number = int(float(text))

        return f"0x{number:03X}"

    except (
        ValueError,
        TypeError
    ):
        return str(value)


# ============================================================
# CREATE ALERT
# ============================================================

def create_alert(row):
    """Create an alert from one suspicious CAN frame."""

    severity = str(
        row.get(
            "severity",
            "Low"
        )
    ).strip()

    if severity not in ALERT_LEVELS:
        return None

    can_id = format_can_id(
        row.get(
            "can_id",
            "Unknown"
        )
    )

    timestamp = str(
        row.get(
            "timestamp",
            ""
        )
    )

    attack_type = str(
        row.get(
            "attack_type",
            "Unknown"
        )
    )

    reason = str(
        row.get(
            "severity_reason",
            "Suspicious CAN traffic"
        )
    )

    rule_score = row.get(
        "rule_score",
        0
    )

    ml_anomaly = row.get(
        "ml_anomaly",
        0
    )

    return {
        "alert_time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "event_timestamp": timestamp,
        "can_id": can_id,
        "attack_type": attack_type,
        "severity": severity,
        "alert_level": ALERT_LEVELS[severity],
        "rule_score": rule_score,
        "ml_anomaly": ml_anomaly,
        "reason": reason,
        "status": "OPEN"
    }


# ============================================================
# GENERATE ALERTS
# ============================================================

def generate_alerts(data):
    """Generate alerts for Medium, High and Critical threats."""

    alerts = []

    for _, row in data.iterrows():

        alert = create_alert(row)

        if alert is not None:
            alerts.append(alert)

    return pd.DataFrame(alerts)


# ============================================================
# SAVE ALERTS
# ============================================================

def save_alerts(alerts):
    """Save generated security alerts."""

    try:

        alerts.to_csv(
            OUTPUT_FILE,
            index=False
        )

        print(
            f"Security alerts saved: {OUTPUT_FILE}"
        )

    except Exception as error:

        print(
            f"Error saving alerts: {error}"
        )


# ============================================================
# ALERT SUMMARY
# ============================================================

def print_summary(alerts):
    """Display alert summary."""

    print()
    print("=" * 60)
    print("CAN-Sentinel Alert Summary")
    print("=" * 60)

    if alerts.empty:

        print(
            "No security alerts generated."
        )

        return

    for level in [
        "Medium",
        "High",
        "Critical"
    ]:

        count = int(
            (
                alerts["severity"] == level
            ).sum()
        )

        print(
            f"{level:<10}: {count}"
        )

    print(
        f"{'Total':<10}: {len(alerts)}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("CAN-Sentinel Alert Manager")
    print("=" * 60)

    data = load_results()

    if data.empty:

        print(
            "ERROR: No threat severity results available."
        )

        return

    required_columns = [
        "can_id",
        "severity"
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in data.columns
    ]

    if missing_columns:

        print(
            "ERROR: Missing required columns:"
        )

        for column in missing_columns:
            print(
                f"- {column}"
            )

        return

    alerts = generate_alerts(
        data
    )

    save_alerts(
        alerts
    )

    print_summary(
        alerts
    )

    print()
    print("=" * 60)
    print(
        "Alert management completed successfully."
    )
    print("=" * 60)


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()