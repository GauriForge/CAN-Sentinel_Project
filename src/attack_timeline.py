"""
CAN-Sentinel - Attack Timeline

Builds a chronological timeline of suspicious
CAN traffic and security events.
"""

import os

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
    "attack_timeline.csv"
)


# ============================================================
# LOAD DATA
# ============================================================

def load_detection_results():
    """Load threat severity results."""

    if not os.path.exists(INPUT_FILE):

        print(
            f"Detection results not found: {INPUT_FILE}"
        )

        return pd.DataFrame()

    try:

        data = pd.read_csv(
            INPUT_FILE
        )

        print(
            f"Loaded {len(data)} detection records."
        )

        return data

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

            number = int(
                text,
                16
            )

        else:

            number = int(
                float(text)
            )

        return f"0x{number:03X}"

    except (
        ValueError,
        TypeError
    ):

        return str(value)


# ============================================================
# EVENT TYPE
# ============================================================

def determine_event_type(row):
    """Determine the security event type."""

    attack_type = str(
        row.get(
            "attack_type",
            ""
        )
    ).strip().lower()

    if attack_type == "flooding":
        return "CAN Flooding"

    if attack_type == "spoofing":
        return "CAN Spoofing"

    if attack_type == "replay":
        return "Replay Attack"

    if attack_type == "injection":
        return "Message Injection"

    if row.get(
        "rule_frequency",
        0
    ) == 1:

        return "Abnormal Frequency"

    if row.get(
        "rule_repetition",
        0
    ) == 1:

        return "Repeated Message"

    if row.get(
        "rule_payload",
        0
    ) == 1:

        return "Suspicious Payload"

    if row.get(
        "rule_timing",
        0
    ) == 1:

        return "Abnormal Timing"

    if row.get(
        "ml_anomaly",
        0
    ) == 1:

        return "ML Anomaly"

    return "Suspicious CAN Activity"


# ============================================================
# BUILD TIMELINE
# ============================================================

def build_timeline(data):
    """Create chronological security event timeline."""

    if data.empty:
        return pd.DataFrame()

    result = data.copy()

    # Keep only suspicious events.
    if "combined_anomaly" in result.columns:

        anomaly = pd.to_numeric(
            result["combined_anomaly"],
            errors="coerce"
        ).fillna(0)

        result = result[
            anomaly == 1
        ].copy()

    elif "severity" in result.columns:

        result = result[
            result["severity"]
            .astype(str)
            .str.strip()
            .isin(
                [
                    "Medium",
                    "High",
                    "Critical"
                ]
            )
        ].copy()

    if result.empty:
        return pd.DataFrame()

    # Convert timestamps for chronological ordering.
    if "timestamp" in result.columns:

        result["event_time"] = pd.to_datetime(
            result["timestamp"],
            errors="coerce"
        )

        result = result.sort_values(
            "event_time"
        )

    # Create timeline fields.
    timeline = pd.DataFrame()

    timeline["event_time"] = result.get(
        "timestamp",
        ""
    )

    timeline["can_id"] = result.get(
        "can_id",
        ""
    ).apply(
        format_can_id
    )

    timeline["attack_type"] = result.apply(
        determine_event_type,
        axis=1
    )

    timeline["severity"] = result.get(
        "severity",
        "Low"
    )

    timeline["rule_score"] = result.get(
        "rule_score",
        0
    )

    timeline["ml_anomaly"] = result.get(
        "ml_anomaly",
        0
    )

    timeline["message_frequency"] = result.get(
        "message_frequency",
        0
    )

    timeline["time_interval"] = result.get(
        "time_interval",
        0
    )

    timeline["reason"] = result.get(
        "severity_reason",
        "Suspicious CAN activity"
    )

    timeline["status"] = "DETECTED"

    timeline = timeline.reset_index(
        drop=True
    )

    # Add sequential event number.
    timeline.insert(
        0,
        "event_id",
        range(
            1,
            len(timeline) + 1
        )
    )

    return timeline


# ============================================================
# SAVE TIMELINE
# ============================================================

def save_timeline(timeline):
    """Save attack timeline to CSV."""

    try:

        timeline.to_csv(
            OUTPUT_FILE,
            index=False
        )

        print(
            f"Attack timeline saved: {OUTPUT_FILE}"
        )

    except Exception as error:

        print(
            f"Error saving attack timeline: {error}"
        )


# ============================================================
# TIMELINE SUMMARY
# ============================================================

def print_summary(timeline):
    """Display timeline summary."""

    print()
    print("=" * 60)
    print("CAN-Sentinel Attack Timeline")
    print("=" * 60)

    if timeline.empty:

        print(
            "No suspicious events found."
        )

        return

    print(
        f"Total security events: {len(timeline)}"
    )

    if "severity" in timeline.columns:

        print()

        for level in [
            "Medium",
            "High",
            "Critical"
        ]:

            count = int(
                (
                    timeline["severity"]
                    .astype(str)
                    .str.strip()
                    == level
                ).sum()
            )

            print(
                f"{level:<10}: {count}"
            )

    if "attack_type" in timeline.columns:

        print()
        print("Event Types:")

        counts = (
            timeline["attack_type"]
            .value_counts()
        )

        for event_type, count in counts.items():

            print(
                f"- {event_type}: {count}"
            )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("CAN-Sentinel Attack Timeline")
    print("=" * 60)

    data = load_detection_results()

    if data.empty:

        print(
            "ERROR: No detection results available."
        )

        return

    timeline = build_timeline(
        data
    )

    if timeline.empty:

        print(
            "No suspicious events available "
            "for the attack timeline."
        )

        # Still create an empty file with
        # the correct structure.
        timeline = pd.DataFrame(
            columns=[
                "event_id",
                "event_time",
                "can_id",
                "attack_type",
                "severity",
                "rule_score",
                "ml_anomaly",
                "message_frequency",
                "time_interval",
                "reason",
                "status"
            ]
        )

    save_timeline(
        timeline
    )

    print_summary(
        timeline
    )

    print()
    print("=" * 60)
    print(
        "Attack timeline generation completed."
    )
    print("=" * 60)


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()