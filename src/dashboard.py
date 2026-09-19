"""
CAN-Sentinel Professional Security Dashboard
"""

import os
import sys

import pandas as pd

from PyQt5.QtCore import QPointF, QRectF, QTimer, Qt
from PyQt5.QtGui import QBrush, QColor, QFont, QPainter, QPen, QPolygonF
from PyQt5.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

RESULT_FILE = os.path.join(
    BASE_DIR,
    "models",
    "threat_severity_results.csv"
)

REFRESH_INTERVAL = 3000


# ============================================================
# CAN MAPPING
# ============================================================

try:
    from can_mapping import get_message_info
except ImportError:
    get_message_info = None


FALLBACK_MAPPING = {
    0x100: ("Engine RPM", "Engine ECU"),
    0x101: ("Vehicle Speed", "Transmission ECU"),
    0x102: ("Engine Temperature", "Engine ECU"),
    0x103: ("Brake Status", "Brake ECU"),
    0x104: ("Steering Angle", "Steering ECU"),
}


# ============================================================
# TRAFFIC GRAPH
# ============================================================

class TrafficGraph(QWidget):
    """Dependency-free CAN traffic activity graph."""

    def __init__(self, parent=None):
        super().__init__(parent)

        self.values = []

        self.setMinimumHeight(190)

    def set_data(self, values):
        """Update graph values."""

        self.values = list(values)[-30:]

        self.update()

    def paintEvent(self, event):
        """Draw the traffic graph."""

        del event

        painter = QPainter(self)

        painter.setRenderHint(
            QPainter.Antialiasing
        )

        painter.fillRect(
            self.rect(),
            QColor("#101820")
        )

        left = 42
        right = 18
        top = 18
        bottom = 30

        graph_width = max(
            1,
            self.width() - left - right
        )

        graph_height = max(
            1,
            self.height() - top - bottom
        )

        # ----------------------------------------------------
        # Grid
        # ----------------------------------------------------

        grid_pen = QPen(
            QColor("#263540"),
            1
        )

        painter.setPen(
            grid_pen
        )

        for index in range(5):

            y = (
                top
                + graph_height
                * index
                / 4
            )

            painter.drawLine(
                left,
                int(y),
                self.width() - right,
                int(y)
            )

        for index in range(6):

            x = (
                left
                + graph_width
                * index
                / 5
            )

            painter.drawLine(
                int(x),
                top,
                int(x),
                self.height() - bottom
            )

        # ----------------------------------------------------
        # Labels
        # ----------------------------------------------------

        painter.setPen(
            QColor("#718392")
        )

        painter.setFont(
            QFont(
                "Segoe UI",
                8
            )
        )

        painter.drawText(
            7,
            top + 5,
            "HIGH"
        )

        painter.drawText(
            12,
            self.height() - bottom,
            "LOW"
        )

        painter.drawText(
            left,
            self.height() - 8,
            "Recent CAN activity"
        )

        # ----------------------------------------------------
        # Empty state
        # ----------------------------------------------------

        if not self.values:

            painter.drawText(
                QRectF(
                    left,
                    top,
                    graph_width,
                    graph_height
                ),
                Qt.AlignCenter,
                "Waiting for CAN traffic data..."
            )

            painter.end()

            return

        # ----------------------------------------------------
        # Convert values
        # ----------------------------------------------------

        numbers = []

        for value in self.values:

            try:
                numbers.append(
                    max(
                        0.0,
                        float(value)
                    )
                )

            except (
                TypeError,
                ValueError
            ):

                numbers.append(
                    0.0
                )

        maximum = (
            max(numbers)
            if numbers
            else 1.0
        )

        if maximum <= 0:
            maximum = 1.0

        # ----------------------------------------------------
        # Create graph points
        # ----------------------------------------------------

        points = []

        count = len(numbers)

        for index, value in enumerate(numbers):

            if count == 1:

                x = (
                    left
                    + graph_width / 2
                )

            else:

                x = (
                    left
                    + graph_width
                    * index
                    / (count - 1)
                )

            y = (
                top
                + graph_height
                - (
                    value
                    / maximum
                    * graph_height
                )
            )

            points.append(
                (x, y)
            )

        # ----------------------------------------------------
        # Filled graph area
        # ----------------------------------------------------

        area = QPolygonF()

        for x, y in points:

            area.append(
                QPointF(
                    x,
                    y
                )
            )

        area.append(
            QPointF(
                points[-1][0],
                self.height() - bottom
            )
        )

        area.append(
            QPointF(
                points[0][0],
                self.height() - bottom
            )
        )

        painter.setPen(
            Qt.NoPen
        )

        painter.setBrush(
            QBrush(
                QColor(
                    48,
                    190,
                    150,
                    45
                )
            )
        )

        painter.drawPolygon(
            area
        )

        # ----------------------------------------------------
        # Main graph line
        # ----------------------------------------------------

        painter.setPen(
            QPen(
                QColor("#4de1b3"),
                3
            )
        )

        painter.setBrush(
            Qt.NoBrush
        )

        for index in range(
            len(points) - 1
        ):

            x1, y1 = points[index]
            x2, y2 = points[index + 1]

            painter.drawLine(
                int(x1),
                int(y1),
                int(x2),
                int(y2)
            )

        # ----------------------------------------------------
        # Graph points
        # ----------------------------------------------------

        painter.setPen(
            Qt.NoPen
        )

        painter.setBrush(
            QBrush(
                QColor("#8af4d0")
            )
        )

        for x, y in points:

            painter.drawEllipse(
                QRectF(
                    x - 3,
                    y - 3,
                    6,
                    6
                )
            )

        painter.end()


# ============================================================
# VEHICLE CAN ARCHITECTURE
# ============================================================

class VehicleWidget(QWidget):
    """Stylized vehicle and ECU/CAN architecture."""

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setMinimumHeight(230)

    def paintEvent(self, event):
        """Draw the vehicle architecture."""

        del event

        painter = QPainter(self)

        painter.setRenderHint(
            QPainter.Antialiasing
        )

        painter.fillRect(
            self.rect(),
            QColor("#101820")
        )

        width = self.width()
        height = self.height()

        # ----------------------------------------------------
        # Title
        # ----------------------------------------------------

        painter.setPen(
            QColor("#f1f5f8")
        )

        painter.setFont(
            QFont(
                "Segoe UI",
                11,
                QFont.Bold
            )
        )

        painter.drawText(
            18,
            25,
            "VEHICLE CAN ARCHITECTURE"
        )

        # ----------------------------------------------------
        # CAN bus
        # ----------------------------------------------------

        bus_y = (
            height / 2
            + 20
        )

        painter.setPen(
            QPen(
                QColor("#3ecfa2"),
                4
            )
        )

        painter.drawLine(
            70,
            int(bus_y),
            width - 70,
            int(bus_y)
        )

        # ----------------------------------------------------
        # Vehicle body
        # ----------------------------------------------------

        car_x = (
            width / 2
            - 100
        )

        car_y = 78

        car_width = 200
        car_height = 70

        painter.setPen(
            QPen(
                QColor("#5c7185"),
                2
            )
        )

        painter.setBrush(
            QBrush(
                QColor("#1c2b37")
            )
        )

        painter.drawRoundedRect(
            QRectF(
                car_x,
                car_y,
                car_width,
                car_height
            ),
            18,
            18
        )

        # ----------------------------------------------------
        # Windows
        # ----------------------------------------------------

        painter.setBrush(
            QBrush(
                QColor("#263d4d")
            )
        )

        painter.drawPolygon(
            QPolygonF(
                [
                    QPointF(
                        car_x + 45,
                        car_y
                    ),
                    QPointF(
                        car_x + 72,
                        car_y - 22
                    ),
                    QPointF(
                        car_x + 98,
                        car_y - 22
                    ),
                    QPointF(
                        car_x + 98,
                        car_y
                    ),
                ]
            )
        )

        painter.drawPolygon(
            QPolygonF(
                [
                    QPointF(
                        car_x + 103,
                        car_y
                    ),
                    QPointF(
                        car_x + 103,
                        car_y - 22
                    ),
                    QPointF(
                        car_x + 128,
                        car_y - 22
                    ),
                    QPointF(
                        car_x + 155,
                        car_y
                    ),
                ]
            )
        )

        # ----------------------------------------------------
        # Wheels
        # ----------------------------------------------------

        painter.setBrush(
            QBrush(
                QColor("#080d12")
            )
        )

        painter.drawEllipse(
            QRectF(
                car_x + 25,
                car_y + 53,
                35,
                35
            )
        )

        painter.drawEllipse(
            QRectF(
                car_x + 140,
                car_y + 53,
                35,
                35
            )
        )

        # ----------------------------------------------------
        # ECU nodes
        # ----------------------------------------------------

        nodes = [
            (
                90,
                bus_y,
                "Engine ECU",
                "0x100 / 0x102"
            ),
            (
                width - 90,
                bus_y,
                "Brake ECU",
                "0x103"
            ),
            (
                width / 2 - 125,
                height - 40,
                "Transmission ECU",
                "0x101"
            ),
            (
                width / 2 + 125,
                height - 40,
                "Steering ECU",
                "0x104"
            ),
        ]

        for x, y, name, can_id in nodes:

            painter.setPen(
                QPen(
                    QColor("#315a50"),
                    2
                )
            )

            painter.drawLine(
                int(x),
                int(y),
                int(x),
                int(bus_y)
            )

            painter.setPen(
                QPen(
                    QColor("#39cfa1"),
                    2
                )
            )

            painter.setBrush(
                QBrush(
                    QColor("#162b29")
                )
            )

            painter.drawEllipse(
                QRectF(
                    x - 50,
                    y - 16,
                    100,
                    32
                )
            )

            painter.setPen(
                QColor("#e8f6f1")
            )

            painter.setFont(
                QFont(
                    "Segoe UI",
                    7,
                    QFont.Bold
                )
            )

            painter.drawText(
                QRectF(
                    x - 47,
                    y - 13,
                    94,
                    12
                ),
                Qt.AlignCenter,
                name
            )

            painter.setPen(
                QColor("#82b8aa")
            )

            painter.setFont(
                QFont(
                    "Segoe UI",
                    7
                )
            )

            painter.drawText(
                QRectF(
                    x - 47,
                    y + 1,
                    94,
                    12
                ),
                Qt.AlignCenter,
                can_id
            )

        painter.end()


# ============================================================
# MAIN DASHBOARD
# ============================================================

class Dashboard(QMainWindow):
    """Main CAN-Sentinel monitoring dashboard."""

    def __init__(self):

        super().__init__()

        self.data = pd.DataFrame()

        self.setWindowTitle(
            "CAN-Sentinel - Automotive Cybersecurity SOC"
        )

        self.resize(
            1450,
            900
        )

        self.setMinimumSize(
            1150,
            720
        )

        self.setup_ui()

        self.timer = QTimer(
            self
        )

        self.timer.timeout.connect(
            self.load_data
        )

        self.timer.start(
            REFRESH_INTERVAL
        )

        self.load_data()

    # ========================================================
    # USER INTERFACE
    # ========================================================

    def setup_ui(self):

        central = QWidget()

        self.setCentralWidget(
            central
        )

        main = QVBoxLayout(
            central
        )

        main.setContentsMargins(
            18,
            16,
            18,
            16
        )

        main.setSpacing(
            10
        )

        # ----------------------------------------------------
        # Header
        # ----------------------------------------------------

        header = QHBoxLayout()

        title_box = QVBoxLayout()

        title = QLabel(
            "CAN-Sentinel"
        )

        title.setObjectName(
            "title"
        )

        subtitle = QLabel(
            "Automotive CAN Bus Intrusion Detection & "
            "Security Operations Center"
        )

        subtitle.setObjectName(
            "subtitle"
        )

        title_box.addWidget(
            title
        )

        title_box.addWidget(
            subtitle
        )

        header.addLayout(
            title_box
        )

        header.addStretch()

        self.status_label = QLabel(
            "● SYSTEM STATUS: WAITING FOR DATA"
        )

        self.status_label.setObjectName(
            "status"
        )

        self.status_label.setProperty(
            "statusLevel",
            "normal"
        )

        self.status_label.setAlignment(
            Qt.AlignCenter
        )

        header.addWidget(
            self.status_label
        )

        main.addLayout(
            header
        )

        # ----------------------------------------------------
        # Summary cards
        # ----------------------------------------------------

        cards = QGridLayout()

        cards.setSpacing(
            10
        )

        self.total_value = self.create_card(
            cards,
            0,
            0,
            "TOTAL FRAMES"
        )

        self.normal_value = self.create_card(
            cards,
            0,
            1,
            "NORMAL FRAMES"
        )

        self.suspicious_value = self.create_card(
            cards,
            0,
            2,
            "SUSPICIOUS FRAMES"
        )

        self.high_value = self.create_card(
            cards,
            0,
            3,
            "HIGH / CRITICAL"
        )

        self.critical_value = self.create_card(
            cards,
            0,
            4,
            "CRITICAL"
        )

        main.addLayout(
            cards
        )

        # ----------------------------------------------------
        # Visualization row
        # ----------------------------------------------------

        visual_row = QHBoxLayout()

        vehicle_panel = self.make_panel()

        vehicle_layout = QVBoxLayout(
            vehicle_panel
        )

        vehicle_layout.addWidget(
            VehicleWidget()
        )

        graph_panel = self.make_panel()

        graph_layout = QVBoxLayout(
            graph_panel
        )

        graph_title = QLabel(
            "CAN TRAFFIC ACTIVITY"
        )

        graph_title.setObjectName(
            "section_title"
        )

        graph_layout.addWidget(
            graph_title
        )

        self.traffic_graph = TrafficGraph()

        graph_layout.addWidget(
            self.traffic_graph
        )

        visual_row.addWidget(
            vehicle_panel,
            1
        )

        visual_row.addWidget(
            graph_panel,
            1
        )

        main.addLayout(
            visual_row
        )

        # ----------------------------------------------------
        # Controls
        # ----------------------------------------------------

        controls = QHBoxLayout()

        self.data_file_label = QLabel(
            "Data source: threat_severity_results.csv"
        )

        self.data_file_label.setObjectName(
            "info"
        )

        controls.addWidget(
            self.data_file_label
        )

        controls.addStretch()

        refresh_button = QPushButton(
            "⟳ Refresh Now"
        )

        refresh_button.clicked.connect(
            self.load_data
        )

        controls.addWidget(
            refresh_button
        )

        main.addLayout(
            controls
        )

        # ----------------------------------------------------
        # Traffic table
        # ----------------------------------------------------

        table_panel = self.make_panel()

        table_layout = QVBoxLayout(
            table_panel
        )

        table_title = QLabel(
            "CAN Traffic & Threat Analysis"
        )

        table_title.setObjectName(
            "section_title"
        )

        table_layout.addWidget(
            table_title
        )

        self.table = QTableWidget(
            0,
            9
        )

        self.table.setHorizontalHeaderLabels(
            [
                "Timestamp",
                "CAN ID",
                "Message",
                "ECU",
                "Attack Type",
                "ML",
                "Rule Score",
                "Severity",
                "Threat Reason",
            ]
        )

        self.table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )

        self.table.setSelectionBehavior(
            QTableWidget.SelectRows
        )

        self.table.setSelectionMode(
            QTableWidget.SingleSelection
        )

        self.table.setAlternatingRowColors(
            True
        )

        self.table.verticalHeader().setVisible(
            False
        )

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        self.table.itemSelectionChanged.connect(
            self.show_selected_event
        )

        table_layout.addWidget(
            self.table
        )

        main.addWidget(
            table_panel,
            2
        )

        # ----------------------------------------------------
        # Bottom information panels
        # ----------------------------------------------------

        bottom = QHBoxLayout()

        self.overview_label = self.make_info_panel(
            bottom,
            "Threat Overview",
            "No detection data available."
        )

        self.event_label = self.make_info_panel(
            bottom,
            "Latest Security Event",
            "No security event detected."
        )

        self.details_label = self.make_info_panel(
            bottom,
            "Selected CAN Frame",
            "Select a CAN frame from the table."
        )

        main.addLayout(
            bottom
        )

        self.apply_styles()

    # ========================================================
    # UI HELPERS
    # ========================================================

    def make_panel(self):

        panel = QFrame()

        panel.setObjectName(
            "panel"
        )

        return panel

    def make_info_panel(
        self,
        parent_layout,
        title,
        text
    ):

        panel = self.make_panel()

        layout = QVBoxLayout(
            panel
        )

        title_label = QLabel(
            title
        )

        title_label.setObjectName(
            "section_title"
        )

        label = QLabel(
            text
        )

        label.setWordWrap(
            True
        )

        layout.addWidget(
            title_label
        )

        layout.addWidget(
            label
        )

        parent_layout.addWidget(
            panel,
            1
        )

        return label

    def create_card(
        self,
        layout,
        row,
        column,
        title
    ):

        frame = QFrame()

        frame.setObjectName(
            "card"
        )

        box = QVBoxLayout(
            frame
        )

        title_label = QLabel(
            title
        )

        title_label.setObjectName(
            "card_title"
        )

        value = QLabel(
            "0"
        )

        value.setObjectName(
            "card_value"
        )

        value.setAlignment(
            Qt.AlignCenter
        )

        box.addWidget(
            title_label
        )

        box.addWidget(
            value
        )

        layout.addWidget(
            frame,
            row,
            column
        )

        return value

    # ========================================================
    # DATA LOADING
    # ========================================================

    def load_data(self):

        if not os.path.exists(
            RESULT_FILE
        ):

            self.data = pd.DataFrame()

            self.update_dashboard()

            self.set_status(
                "● SYSTEM STATUS: WAITING FOR DETECTION RESULTS",
                "normal"
            )

            self.data_file_label.setText(
                "Data source: waiting for "
                "threat_severity_results.csv"
            )

            return

        try:

            self.data = pd.read_csv(
                RESULT_FILE
            ).fillna("")

            self.update_dashboard()

            self.update_security_status()

            self.data_file_label.setText(
                "Data source: "
                "models/threat_severity_results.csv"
                f" | {len(self.data)} frames"
            )

        except Exception as error:

            self.data = pd.DataFrame()

            self.update_dashboard()

            self.set_status(
                "● SYSTEM STATUS: DATA ERROR",
                "critical"
            )

            self.data_file_label.setText(
                f"Data error: {error}"
            )

    # ========================================================
    # DASHBOARD UPDATE
    # ========================================================

    def update_dashboard(self):

        if self.data.empty:

            for label in (
                self.total_value,
                self.normal_value,
                self.suspicious_value,
                self.high_value,
                self.critical_value,
            ):

                label.setText(
                    "0"
                )

            self.table.setRowCount(
                0
            )

            self.overview_label.setText(
                "No detection data available."
            )

            self.event_label.setText(
                "No security event detected."
            )

            self.details_label.setText(
                "Select a CAN frame from the table."
            )

            self.traffic_graph.set_data(
                []
            )

            return

        total = len(
            self.data
        )

        suspicious = self.count_suspicious(
            self.data
        )

        high_critical = self.count_severity(
            self.data,
            {
                "High",
                "Critical"
            }
        )

        critical = self.count_severity(
            self.data,
            {
                "Critical"
            }
        )

        normal = max(
            0,
            total - suspicious
        )

        self.total_value.setText(
            str(total)
        )

        self.normal_value.setText(
            str(normal)
        )

        self.suspicious_value.setText(
            str(suspicious)
        )

        self.high_value.setText(
            str(high_critical)
        )

        self.critical_value.setText(
            str(critical)
        )

        self.update_table()

        self.update_overview()

        self.update_latest_event()

        self.update_traffic_graph()

    # ========================================================
    # COUNTERS
    # ========================================================

    def count_suspicious(
        self,
        data
    ):

        if "combined_anomaly" in data.columns:

            values = pd.to_numeric(
                data["combined_anomaly"],
                errors="coerce"
            ).fillna(0)

            return int(
                (values == 1).sum()
            )

        if "severity" in data.columns:

            severity = (
                data["severity"]
                .astype(str)
                .str.strip()
                .str.lower()
            )

            return int(
                (
                    ~severity.isin(
                        {
                            "low",
                            "normal",
                            ""
                        }
                    )
                ).sum()
            )

        return 0

    def count_severity(
        self,
        data,
        levels
    ):

        if "severity" not in data.columns:
            return 0

        severity = (
            data["severity"]
            .astype(str)
            .str.strip()
        )

        return int(
            severity.isin(
                levels
            ).sum()
        )

    # ========================================================
    # TABLE
    # ========================================================

    def update_table(self):

        display = (
            self.data
            .tail(100)
            .iloc[::-1]
            .reset_index(drop=True)
        )

        self.table.setRowCount(
            len(display)
        )

        for row_index, row in display.iterrows():

            can_id = self.format_can_id(
                row.get(
                    "can_id",
                    ""
                )
            )

            message, ecu = self.get_mapping(
                can_id
            )

            values = [
                str(
                    row.get(
                        "timestamp",
                        ""
                    )
                ),
                can_id,
                message,
                ecu,
                str(
                    row.get(
                        "attack_type",
                        "none"
                    )
                ),
                self.get_ml_status(
                    row
                ),
                self.safe_number(
                    row.get(
                        "rule_score",
                        0
                    )
                ),
                str(
                    row.get(
                        "severity",
                        "Low"
                    )
                ),
                str(
                    row.get(
                        "severity_reason",
                        row.get(
                            "threat_reason",
                            ""
                        )
                    )
                ),
            ]

            for column_index, value in enumerate(
                values
            ):

                item = QTableWidgetItem(
                    value
                )

                item.setToolTip(
                    value
                )

                self.table.setItem(
                    row_index,
                    column_index,
                    item
                )

            severity = (
                str(
                    row.get(
                        "severity",
                        "Low"
                    )
                )
                .strip()
                .lower()
            )

            if severity == "critical":

                self.set_row_background(
                    row_index,
                    QColor("#3a2025")
                )

            elif severity == "high":

                self.set_row_background(
                    row_index,
                    QColor("#352c1d")
                )

    def set_row_background(
        self,
        row,
        color
    ):

        for column in range(
            self.table.columnCount()
        ):

            item = self.table.item(
                row,
                column
            )

            if item:

                item.setBackground(
                    color
                )

    # ========================================================
    # GRAPH
    # ========================================================

    def update_traffic_graph(self):

        recent = self.data.tail(
            30
        )

        if "message_frequency" in recent.columns:

            values = pd.to_numeric(
                recent["message_frequency"],
                errors="coerce"
            ).fillna(
                0
            ).tolist()

        else:

            values = list(
                range(
                    1,
                    len(recent) + 1
                )
            )

        self.traffic_graph.set_data(
            values
        )

    # ========================================================
    # THREAT OVERVIEW
    # ========================================================

    def update_overview(self):

        counts = {
            "Low": 0,
            "Medium": 0,
            "High": 0,
            "Critical": 0,
        }

        if "severity" in self.data.columns:

            severity_counts = (
                self.data["severity"]
                .astype(str)
                .str.strip()
                .value_counts()
            )

            for level in counts:

                counts[level] = int(
                    severity_counts.get(
                        level,
                        0
                    )
                )

        if "can_id" in self.data.columns:

            unique_ids = int(
                self.data["can_id"]
                .astype(str)
                .nunique()
            )

        else:

            unique_ids = 0

        self.overview_label.setText(
            f"LOW : {counts['Low']}\n"
            f"MEDIUM : {counts['Medium']}\n"
            f"HIGH : {counts['High']}\n"
            f"CRITICAL : {counts['Critical']}\n\n"
            f"Suspicious frames : "
            f"{self.count_suspicious(self.data)}\n"
            f"Unique CAN IDs : {unique_ids}"
        )

    # ========================================================
    # LATEST EVENT
    # ========================================================

    def update_latest_event(self):

        if "severity" not in self.data.columns:

            self.event_label.setText(
                "Severity information unavailable."
            )

            return

        dangerous = self.data[
            self.data["severity"]
            .astype(str)
            .str.strip()
            .isin(
                {
                    "High",
                    "Critical"
                }
            )
        ]

        if dangerous.empty:

            self.event_label.setText(
                "No High or Critical "
                "security event detected."
            )

            return

        row = dangerous.iloc[-1]

        can_id = self.format_can_id(
            row.get(
                "can_id",
                ""
            )
        )

        message, ecu = self.get_mapping(
            can_id
        )

        self.event_label.setText(
            f"Time: {row.get('timestamp', 'Unknown')}\n"
            f"CAN ID: {can_id}\n"
            f"Message: {message}\n"
            f"ECU: {ecu}\n"
            f"Attack: {row.get('attack_type', 'Unknown')}\n"
            f"Severity: {row.get('severity', 'Unknown')}\n"
            f"Reason: {row.get('severity_reason', row.get('threat_reason', 'Unknown'))}"
        )

    # ========================================================
    # SELECTED EVENT
    # ========================================================

    def show_selected_event(self):

        selected = (
            self.table
            .selectionModel()
            .selectedRows()
        )

        if not selected:

            self.details_label.setText(
                "Select a CAN frame from the table."
            )

            return

        row_index = selected[0].row()

        values = []

        for column in range(9):

            item = self.table.item(
                row_index,
                column
            )

            values.append(
                item.text()
                if item
                else ""
            )

        original = self.find_original_row(
            values[0],
            values[1]
        )

        if original is not None:

            dlc = original.get(
                "dlc",
                "Unknown"
            )

            payload = original.get(
                "payload",
                "Unknown"
            )

        else:

            dlc = "Unknown"
            payload = "Unknown"

        self.details_label.setText(
            f"Timestamp: {values[0]}\n"
            f"CAN ID: {values[1]}\n"
            f"Message: {values[2]}\n"
            f"ECU: {values[3]}\n"
            f"DLC: {dlc}\n"
            f"Payload: {payload}\n"
            f"Attack Type: {values[4]}\n"
            f"ML Status: {values[5]}\n"
            f"Rule Score: {values[6]}\n"
            f"Severity: {values[7]}\n"
            f"Threat Reason: {values[8]}"
        )

    # ========================================================
    # ORIGINAL ROW
    # ========================================================

    def find_original_row(
        self,
        timestamp,
        can_id
    ):

        if self.data.empty:
            return None

        for _, row in self.data.iterrows():

            row_timestamp = str(
                row.get(
                    "timestamp",
                    ""
                )
            )

            row_can_id = self.format_can_id(
                row.get(
                    "can_id",
                    ""
                )
            )

            if (
                row_timestamp == timestamp
                and row_can_id == can_id
            ):

                return row

        return None

    # ========================================================
    # CAN-ID FORMAT
    # ========================================================

    def format_can_id(
        self,
        value
    ):

        try:

            text = str(
                value
            ).strip()

            if not text:
                return "Unknown"

            return f"0x{int(text, 0):03X}"

        except (
            ValueError,
            TypeError
        ):

            try:

                return f"0x{int(float(value)):03X}"

            except (
                ValueError,
                TypeError
            ):

                return str(
                    value
                )

    # ========================================================
    # CAN MAPPING
    # ========================================================

    def get_mapping(
        self,
        can_id
    ):

        try:

            number = int(
                str(can_id),
                0
            )

        except (
            ValueError,
            TypeError
        ):

            return (
                "Unknown",
                "Unknown"
            )

        if get_message_info is not None:

            try:

                info = get_message_info(
                    number
                )

                if isinstance(
                    info,
                    dict
                ):

                    return (
                        str(
                            info.get(
                                "name",
                                "Unknown"
                            )
                        ),
                        str(
                            info.get(
                                "ecu",
                                "Unknown"
                            )
                        )
                    )

            except Exception:
                pass

        return FALLBACK_MAPPING.get(
            number,
            (
                "Unknown",
                "Unknown"
            )
        )

    # ========================================================
    # ML STATUS
    # ========================================================

    def get_ml_status(
        self,
        row
    ):

        value = row.get(
            "ml_anomaly",
            row.get(
                "ml_prediction",
                0
            )
        )

        try:

            return (
                "Anomaly"
                if int(
                    float(value)
                ) == 1
                else "Normal"
            )

        except (
            ValueError,
            TypeError
        ):

            text = (
                str(value)
                .strip()
                .lower()
            )

            return (
                "Anomaly"
                if text in {
                    "anomaly",
                    "true",
                    "yes"
                }
                else "Normal"
            )

    # ========================================================
    # SAFE NUMBER
    # ========================================================

    def safe_number(
        self,
        value
    ):

        try:

            number = float(
                value
            )

            if number.is_integer():

                return str(
                    int(number)
                )

            return f"{number:.2f}"

        except (
            ValueError,
            TypeError
        ):

            return "0"

    # ========================================================
    # SECURITY STATUS
    # ========================================================

    def update_security_status(self):

        if (
            self.data.empty
            or "severity"
            not in self.data.columns
        ):

            self.set_status(
                "● SYSTEM STATUS: MONITORING",
                "normal"
            )

            return

        severity = (
            self.data["severity"]
            .astype(str)
            .str.strip()
        )

        if (
            severity == "Critical"
        ).any():

            self.set_status(
                "● SYSTEM STATUS: CRITICAL THREAT",
                "critical"
            )

        elif (
            severity == "High"
        ).any():

            self.set_status(
                "● SYSTEM STATUS: HIGH THREAT",
                "high"
            )

        elif (
            ~severity.isin(
                {
                    "Low",
                    "Normal",
                    ""
                }
            )
        ).any():

            self.set_status(
                "● SYSTEM STATUS: SUSPICIOUS ACTIVITY",
                "warning"
            )

        else:

            self.set_status(
                "● SYSTEM STATUS: NORMAL",
                "normal"
            )

    def set_status(
        self,
        text,
        level
    ):

        self.status_label.setText(
            text
        )

        self.status_label.setProperty(
            "statusLevel",
            level
        )

        self.status_label.style().unpolish(
            self.status_label
        )

        self.status_label.style().polish(
            self.status_label
        )

    # ========================================================
    # STYLES
    # ========================================================

    def apply_styles(self):

        self.setStyleSheet(
            """
            QMainWindow {
                background: #0b1117;
            }

            QWidget {
                color: #e8edf3;
                font-family: "Segoe UI";
            }

            #title {
                font-size: 30px;
                font-weight: bold;
                color: #ffffff;
            }

            #subtitle {
                color: #80909f;
                font-size: 13px;
            }

            #status {
                background: #13251f;
                border: 1px solid #28634f;
                border-radius: 7px;
                padding: 10px 18px;
                color: #63e6b5;
                font-weight: bold;
                font-size: 12px;
            }

            #status[statusLevel="critical"] {
                background: #351a20;
                border-color: #a94352;
                color: #ff7182;
            }

            #status[statusLevel="high"] {
                background: #332718;
                border-color: #91652d;
                color: #f2bd68;
            }

            #status[statusLevel="warning"] {
                background: #302b18;
                border-color: #766526;
                color: #e8d768;
            }

            #status[statusLevel="normal"] {
                background: #13251f;
                border-color: #28634f;
                color: #63e6b5;
            }

            #info {
                color: #738493;
                font-size: 11px;
            }

            #card {
                background: #131b23;
                border: 1px solid #263541;
                border-radius: 9px;
            }

            #card_title {
                color: #788b9d;
                font-size: 11px;
                font-weight: bold;
                letter-spacing: 1px;
            }

            #card_value {
                color: #f3f7fa;
                font-size: 25px;
                font-weight: bold;
            }

            #panel {
                background: #131b23;
                border: 1px solid #263541;
                border-radius: 9px;
            }

            #section_title {
                color: #f1f5f8;
                font-size: 14px;
                font-weight: bold;
                padding: 3px;
            }

            QPushButton {
                background: #1d2b37;
                color: #ffffff;
                border: 1px solid #3b5060;
                border-radius: 6px;
                padding: 8px 18px;
                font-weight: bold;
            }

            QPushButton:hover {
                background: #294050;
            }

            QTableWidget {
                background: #0e151c;
                alternate-background-color: #151f28;
                color: #e8edf3;
                border: none;
                gridline-color: #26333e;
                selection-background-color: #29465a;
                selection-color: #ffffff;
                font-size: 11px;
            }

            QHeaderView::section {
                background: #1a2631;
                color: #dce5eb;
                padding: 8px;
                border: none;
                border-right: 1px solid #2a3945;
                font-weight: bold;
                font-size: 11px;
            }

            QTableWidget::item {
                padding: 5px;
            }

            QScrollBar:vertical {
                background: #0d141a;
                width: 10px;
                margin: 0px;
            }

            QScrollBar::handle:vertical {
                background: #304452;
                border-radius: 5px;
                min-height: 25px;
            }
            """
        )

    # ========================================================
    # CLOSE EVENT
    # ========================================================

    def closeEvent(
        self,
        event
    ):

        self.timer.stop()

        event.accept()


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

def main():

    app = QApplication(
        sys.argv
    )

    window = Dashboard()

    window.show()

    sys.exit(
        app.exec_()
    )


if __name__ == "__main__":
    main()

