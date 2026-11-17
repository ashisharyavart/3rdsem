"""
CyberGuard Desktop - Threat History Widget & Inspector Dialog
Displays searchable, categorized table of detected screen security events.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QLabel, QDialog, QTextEdit, QMessageBox
)
from PySide6.QtCore import Qt, Signal
from typing import List, Dict, Any


class ThreatDetailsDialog(QDialog):
    """Inspect full details of a specific detected threat event."""
    def __init__(self, item_data: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Threat Event Inspection")
        self.setMinimumSize(500, 360)
        self.setStyleSheet("""
            QDialog {
                background-color: #0F172A;
                color: #F8FAFC;
                font-family: 'Segoe UI', sans-serif;
            }
            QLabel {
                color: #E2E8F0;
                font-size: 13px;
            }
            QTextEdit {
                background-color: #1E293B;
                border: 1px solid #334155;
                border-radius: 6px;
                color: #F8FAFC;
                font-family: Consolas, monospace;
                font-size: 12px;
                padding: 8px;
            }
            QPushButton {
                background-color: #1E293B;
                color: #F8FAFC;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 16px;
            }
            QPushButton:hover {
                background-color: #334155;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        header = QLabel(f"Threat Score: {item_data.get('score', 0)}/100  |  Severity: {item_data.get('severity', 'Unknown')}")
        header.setStyleSheet("font-size: 15px; font-weight: bold; color: #38BDF8;")
        layout.addWidget(header)

        time_lbl = QLabel(f"Timestamp: {item_data.get('timestamp', 'N/A')}")
        layout.addWidget(time_lbl)

        cat_lbl = QLabel(f"Categories: {item_data.get('categories', 'None')}")
        layout.addWidget(cat_lbl)

        domain_val = item_data.get('domain', '') or 'None detected'
        domain_lbl = QLabel(f"Extracted Domain: {domain_val}")
        layout.addWidget(domain_lbl)

        layout.addWidget(QLabel("Analysis & Indicators:"))
        details_box = QTextEdit()
        details_box.setReadOnly(True)
        explanation = item_data.get("explanation", "No detailed explanation.")
        details_box.setPlainText(explanation)
        layout.addWidget(details_box)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)


class ThreatHistoryWidget(QWidget):
    """
    Table widget displaying recent threat detections with inspection and clear options.
    """
    threat_selected = Signal(dict)
    clear_history_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Header bar
        header_bar = QHBoxLayout()
        title_lbl = QLabel("Recent Threat Detections")
        title_lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: #E2E8F0;")
        header_bar.addWidget(title_lbl)
        header_bar.addStretch()

        self.clear_btn = QPushButton("Clear History")
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #1E293B;
                color: #94A3B8;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 11px;
            }
            QPushButton:hover {
                color: #EF4444;
                border-color: #EF4444;
            }
        """)
        self.clear_btn.clicked.connect(self._on_clear_clicked)
        header_bar.addWidget(self.clear_btn)
        layout.addLayout(header_bar)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Score", "Severity", "Categories", "Summary"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.doubleClicked.connect(self._on_row_double_clicked)

        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #1E293B;
                border: 1px solid #334155;
                border-radius: 6px;
                gridline-color: #334155;
                color: #F8FAFC;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #0F172A;
                color: #94A3B8;
                font-weight: bold;
                font-size: 11px;
                border: none;
                border-bottom: 1px solid #334155;
                padding: 6px;
            }
            QTableWidget::item:selected {
                background-color: #334155;
                color: #38BDF8;
            }
        """)

        layout.addWidget(self.table)
        self.data_rows: List[Dict[str, Any]] = []

    def set_threats(self, threats: List[Dict[str, Any]]):
        self.data_rows = threats
        self.table.setRowCount(len(threats))

        for row_idx, item in enumerate(threats):
            # Timestamp
            ts_item = QTableWidgetItem(str(item.get("timestamp", "")))
            ts_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row_idx, 0, ts_item)

            # Score
            score = item.get("score", 0)
            score_item = QTableWidgetItem(str(score))
            score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row_idx, 1, score_item)

            # Severity with color
            severity = str(item.get("severity", "Low")).upper()
            sev_item = QTableWidgetItem(severity)
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if severity == "CRITICAL":
                sev_item.setForeground(Qt.GlobalColor.red)
            elif severity == "HIGH":
                sev_item.setForeground(Qt.GlobalColor.darkYellow)
            elif severity == "SUSPICIOUS":
                sev_item.setForeground(Qt.GlobalColor.yellow)
            else:
                sev_item.setForeground(Qt.GlobalColor.green)
            self.table.setItem(row_idx, 2, sev_item)

            # Categories
            cats = item.get("categories", "")
            if isinstance(cats, list):
                cats = ", ".join(cats)
            cat_item = QTableWidgetItem(str(cats))
            self.table.setItem(row_idx, 3, cat_item)

            # Summary
            expl = item.get("explanation", "")
            if isinstance(expl, list):
                expl = "; ".join(expl)
            first_line = expl.split("\n")[0] if expl else "Threat detected"
            summary_item = QTableWidgetItem(first_line)
            self.table.setItem(row_idx, 4, summary_item)

    def add_threat(self, threat: Dict[str, Any]):
        self.data_rows.insert(0, threat)
        self.set_threats(self.data_rows[:200])

    def _on_row_double_clicked(self, index):
        row = index.row()
        if 0 <= row < len(self.data_rows):
            dialog = ThreatDetailsDialog(self.data_rows[row], self)
            dialog.exec()

    def _on_clear_clicked(self):
        reply = QMessageBox.question(
            self,
            "Clear Threat History",
            "Are you sure you want to clear all recorded threat history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.clear_history_requested.emit()
            self.set_threats([])

