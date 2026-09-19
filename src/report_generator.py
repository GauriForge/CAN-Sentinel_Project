"""
CAN-Sentinel - Security Report Generator

Generates a security assessment report from
CAN detection and attack timeline results.
"""

import os
from datetime import datetime

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

SEVERITY_FILE = os.path.join(
    BASE_DIR,
    "models",
    "threat_severity_results.csv"
)

ALERT_FILE = os.path.join(
    BASE_DIR,
    "models",
    "security_alerts.csv"
)

TIMELINE_FILE = os.path.join(
    BASE_DIR,
    "models",
    "attack_timeline.csv"
)

REPORT_DIR = os.path.join(
    BASE_DIR,
    "models"
)

REPORT_FILE = os.path.join(
    REPORT_DIR,
    "CAN_Sentinel_Security_Report.pdf"
)


# ============================================================
# LOAD DATA
# ============================================================

def load_csv(path):
    """Load a CSV file if it exists."""

    if not os.path.exists(path):
        return pd.DataFrame()

    try:
        return pd.read_csv(path)

    except Exception as error:
        print(
            f"Error loading {path}: {error}"
        )
        return pd.DataFrame()


# ============================================================
# SUMMARY
# ============================================================

def create_summary(severity_data):
    """Create report summary values."""

    total = len(severity_data)

    suspicious = 0
    low = 0
    medium = 0
    high = 0
    critical = 0

    if "severity" in severity_data.columns:

        severity = (
            severity_data["severity"]
            .astype(str)
            .str.strip()
        )

        low = int(
            (severity == "Low").sum()
        )

        medium = int(
            (severity == "Medium").sum()
        )

        high = int(
            (severity == "High").sum()
        )

        critical = int(
            (severity == "Critical").sum()
        )

        suspicious = (
            medium + high + critical
        )

    elif "combined_anomaly" in severity_data.columns:

        anomaly = pd.to_numeric(
            severity_data["combined_anomaly"],
            errors="coerce"
        ).fillna(0)

        suspicious = int(
            (anomaly == 1).sum()
        )

    return {
        "total": total,
        "suspicious": suspicious,
        "low": low,
        "medium": medium,
        "high": high,
        "critical": critical,
    }


# ============================================================
# TOP CAN IDS
# ============================================================

def get_top_can_ids(data):
    """Return the most frequently detected CAN IDs."""

    if data.empty or "can_id" not in data.columns:
        return []

    counts = (
        data["can_id"]
        .astype(str)
        .value_counts()
        .head(5)
    )

    return [
        [str(can_id), str(count)]
        for can_id, count in counts.items()
    ]


# ============================================================
# ATTACK TYPES
# ============================================================

def get_attack_types(data):
    """Return detected attack/event types."""

    if data.empty:
        return []

    column = (
        "attack_type"
        if "attack_type" in data.columns
        else None
    )

    if column is None:
        return []

    counts = (
        data[column]
        .astype(str)
        .value_counts()
    )

    return [
[str(name), str(count)]
        for name, count in counts.items()
    ]


# ============================================================
# REPORT GENERATION
# ============================================================

def generate_report(
    severity_data,
    alert_data,
    timeline_data
):
    """Generate the final PDF security report."""

    os.makedirs(
        REPORT_DIR,
        exist_ok=True
    )

    summary = create_summary(
        severity_data
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["BodyText"]

    document = SimpleDocTemplate(
        REPORT_FILE,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    elements = []

    # --------------------------------------------------------
    # Title
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "CAN-Sentinel Security Assessment Report",
            title_style
        )
    )

    elements.append(
        Spacer(1, 12)
    )

    elements.append(
        Paragraph(
            f"Generated: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            normal_style
        )
    )

    elements.append(
        Spacer(1, 20)
    )

    # --------------------------------------------------------
    # Executive Summary
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "1. Executive Summary",
            heading_style
        )
    )

    summary_text = (
        f"CAN-Sentinel analyzed {summary['total']} "
        f"CAN traffic records. "
        f"{summary['suspicious']} suspicious records "
        f"were identified by the detection pipeline. "
        f"The analysis classified threats into Low, "
        f"Medium, High, and Critical severity levels."
    )

    elements.append(
        Paragraph(
            summary_text,
            normal_style
        )
    )

    elements.append(
        Spacer(1, 15)
    )

    # --------------------------------------------------------
    # Severity Summary
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "2. Threat Severity Summary",
            heading_style
        )
    )

    severity_table = Table(
        [
            ["Severity", "Detected Events"],
            ["Low", str(summary["low"])],
            ["Medium", str(summary["medium"])],
            ["High", str(summary["high"])],
            ["Critical", str(summary["critical"])],
        ],
        colWidths=[
            2.5 * inch,
            2.5 * inch
        ]
    )

    severity_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#263442")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "ALIGN",
                (1, 1),
                (-1, -1),
                "CENTER"
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, 0),
                8
            ),
        ])
    )

    elements.append(
        severity_table
    )

    elements.append(
        Spacer(1, 20)
    )

    # --------------------------------------------------------
    # Alert Summary
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "3. Security Alerts",
            heading_style
        )
    )

    alert_count = len(
        alert_data
    )

    elements.append(
        Paragraph(
            f"Total security alerts generated: "
            f"{alert_count}",
            normal_style
        )
    )

    elements.append(
        Spacer(1, 15)
    )

    # --------------------------------------------------------
    # Attack Timeline
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "4. Attack Timeline",
            heading_style
        )
    )

    timeline_count = len(
        timeline_data
    )

    elements.append(
        Paragraph(
            f"Total suspicious events recorded: "
            f"{timeline_count}",
            normal_style
        )
    )

    elements.append(
        Spacer(1, 12)
    )

    if not timeline_data.empty:

        timeline_rows = [
            [
                "Time",
                "CAN ID",
                "Event",
                "Severity"
            ]
        ]

        for _, row in timeline_data.tail(10).iterrows():

            timeline_rows.append([
                str(
                    row.get(
                        "event_time",
                        ""
                    )
                ),
                str(
                    row.get(
                        "can_id",
                        ""
                    )
                ),
                str(
                    row.get(
                        "attack_type",
                        ""
                    )
                ),
                str(
                    row.get(
                        "severity",
                        ""
                    )
                ),
            ])

        timeline_table = Table(
            timeline_rows,
            colWidths=[
                1.45 * inch,
                0.9 * inch,
                2.1 * inch,
                1.0 * inch
            ]
        )

        timeline_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
(-1, 0),
                    colors.HexColor("#263442")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),
            ])
        )

        elements.append(
            timeline_table
        )

    else:

        elements.append(
            Paragraph(
                "No suspicious events were available.",
                normal_style
            )
        )

    elements.append(
        Spacer(1, 20)
    )

    # --------------------------------------------------------
    # CAN ID Analysis
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "5. CAN ID Activity",
            heading_style
        )
    )

    can_ids = get_top_can_ids(
        severity_data
    )

    if can_ids:

        can_table = Table(
            [
                ["CAN ID", "Occurrences"]
            ] + can_ids,
            colWidths=[
                2.5 * inch,
                2.5 * inch
            ]
        )

        can_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#263442")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
            ])
        )

        elements.append(
            can_table
        )

    else:

        elements.append(
            Paragraph(
                "No CAN ID activity data available.",
                normal_style
            )
        )

    elements.append(
        Spacer(1, 20)
    )

    # --------------------------------------------------------
    # Attack Type Analysis
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "6. Detected Event Types",
            heading_style
        )
    )

    attack_types = get_attack_types(
        timeline_data
    )

    if attack_types:

        attack_table = Table(
            [
                ["Event Type", "Occurrences"]
            ] + attack_types,
            colWidths=[
                3.5 * inch,
                1.5 * inch
            ]
        )

        attack_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#263442")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),
            ])
        )

        elements.append(
            attack_table
        )

    else:

        elements.append(
            Paragraph(
                "No specific attack types recorded.",
                normal_style
            )
        )

    elements.append(
        Spacer(1, 20)
    )

    # --------------------------------------------------------
    # Detection Method
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "7. Detection Method",
            heading_style
        )
    )

    detection_text = (
        "CAN-Sentinel uses a hybrid detection approach. "
        "Rule-based analysis evaluates CAN traffic "
        "frequency, timing, repetition, and payload "
        "characteristics. Machine learning analysis "
        "provides additional anomaly detection. "
        "The resulting evidence is combined to assign "
        "a threat severity level."
    )

    elements.append(
        Paragraph(
            detection_text,
            normal_style
        )
    )

    elements.append(
        Spacer(1, 20)
    )

    # --------------------------------------------------------
    # Conclusion
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "8. Conclusion",
            heading_style
        )
    )

    conclusion = (
        "The CAN-Sentinel analysis provides a structured "
        "view of CAN bus security activity. Detected "
        "events are classified by severity and preserved "
        "in security alerts and an attack timeline. "
        "The generated report can be used as evidence "
        "for security analysis, testing, and project "
        "documentation."
    )

    elements.append(
        Paragraph(
            conclusion,
            normal_style
        )
    )

    document.build(
        elements
    )

    return REPORT_FILE


# ============================================================
# MAIN
# ============================================================

def main():
    """Run the security report generation process."""

    print()
    print("=" * 60)
    print("CAN-Sentinel Security Report Generator")
    print("=" * 60)

    severity_data = load_csv(
        SEVERITY_FILE
    )

    alert_data = load_csv(
        ALERT_FILE
    )

    timeline_data = load_csv(
        TIMELINE_FILE
    )

    if severity_data.empty:
        print(
            "ERROR: Threat severity results not found."
        )

        print(
            "Run threat_severity.py first."
        )

        return

    try:
        report_path = generate_report(
            severity_data,
            alert_data,
            timeline_data
        )

        print()
        print(
            "Security report generated:"
        )

        print(
            report_path
        )

    except Exception as error:
        print()
        print(
            f"Error generating report: {error}"
        )

        return


if __name__ == "__main__":
    main()