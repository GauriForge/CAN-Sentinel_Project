"""
CAN-Sentinel - Main Controller

Runs the complete CAN-Sentinel detection pipeline.
"""

import os
import sys
import subprocess


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

SRC_DIR = os.path.join(
    BASE_DIR,
    "src"
)


PIPELINE = [
    ("Feature Extraction", "feature_extraction.py"),
    ("ML Anomaly Detection", "anomaly_detector.py"),
    ("Rule Detection", "rule_detector.py"),
    ("Threat Severity", "threat_severity.py"),
    ("Alert Manager", "alert_manager.py"),
    ("Attack Timeline", "attack_timeline.py"),
    ("Security Report", "report_generator.py"),
]


def run_module(name, filename):
    """Run one CAN-Sentinel module."""

    print()
    print("=" * 60)
    print(name)
    print("=" * 60)

    file_path = os.path.join(
        SRC_DIR,
        filename
    )

    if not os.path.exists(file_path):
        print(
            f"ERROR: File not found: {file_path}"
        )
        return False

    try:
        result = subprocess.run(
            [sys.executable, file_path],
            cwd=BASE_DIR
        )

        if result.returncode != 0:
            print(
                f"ERROR: {name} failed."
            )
            return False

        print(
            f"{name} completed successfully."
        )

        return True

    except Exception as error:
        print(
            f"ERROR running {name}: {error}"
        )
        return False


def launch_dashboard():
    """Launch the CAN-Sentinel dashboard."""

    print()
    print("=" * 60)
    print("Launching CAN-Sentinel Dashboard")
    print("=" * 60)

    dashboard_path = os.path.join(
        SRC_DIR,
        "dashboard.py"
    )

    if not os.path.exists(dashboard_path):
        print(
            f"ERROR: Dashboard not found: {dashboard_path}"
        )
        return

    try:
        subprocess.run(
            [sys.executable, dashboard_path],
            cwd=BASE_DIR
        )

    except Exception as error:
        print(
            f"ERROR launching dashboard: {error}"
        )


def main():
    """Run the complete CAN-Sentinel pipeline."""

    print()
    print("=" * 60)
    print("CAN-SENTINEL")
    print("Automotive CAN Bus Security Monitoring System")
    print("=" * 60)

    print()
    print("Starting security analysis pipeline...")

    for name, filename in PIPELINE:

        success = run_module(
            name,
            filename
        )

        if not success:
            print()
            print("=" * 60)
            print("PIPELINE STOPPED")
            print("=" * 60)
            return

    print()
    print("=" * 60)
    print("ALL SECURITY ANALYSIS MODULES COMPLETED")
    print("=" * 60)

    launch_dashboard()


if __name__ == "__main__":
    main()