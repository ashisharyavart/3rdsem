"""
CyberGuard Desktop - Desktop Threat Alert Notification
Displays non-intrusive floating warnings when high or critical security threats are detected.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame, QScrollArea
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIcon
from config import PROJECT_ROOT


class ThreatAlertOverlay(QDialog):
    """
    Floating desktop alert notification window.
    Designed with a restrained, informative, non-alarmist appearance.
    """
    view_details_requested = Signal(dict)

    def __init__(self, threat_data: dict, parent=None):
        super().__init__(parent)
        self.threat_data = threat_data
        self.setWindowTitle("CyberGuard Security Advisory")
        self.setWindowFlags(
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setFixedSize(480, 290)
        self._init_ui()

    def _init_ui(self):
        score = self.threat_data.get("score", 0)
        severity = self.threat_data.get("severity", "Suspicious").upper()
        categories = self.threat_data.get("categories", [])
        reasons = self.threat_data.get("reasons", [])

        # Color accents based on severity
        if severity == "CRITICAL":
            accent_color = "#EF4444"
            bg_accent = "#450A0A"
        elif severity == "HIGH":
            accent_color = "#F97316"
            bg_accent = "#431407"
        else:
            accent_color = "#EAB308"
            bg_accent = "#422006"

        self.setStyleSheet(f"""
            QDialog {{
                background-color: #0F172A;
                border: 2px solid {accent_color};
                border-radius: 10px;
                color: #F8FAFC;
                font-family: 'Segoe UI', sans-serif;
            }}
            QLabel {{
                color: #F8FAFC;
            }}
            QPushButton {{
                background-color: #1E293B;
                color: #F8FAFC;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 12px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: #334155;
            }}
            QPushButton#actionBtn {{
                background-color: {accent_color};
                color: #FFFFFF;
                font-weight: bold;
                border: none;
            }}
            QPushButton#actionBtn:hover {{
                opacity: 0.9;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Header: Icon + Title + Severity Pill
        header = QHBoxLayout()
        icon_lbl = QLabel("🛡️")
        icon_lbl.setStyleSheet("font-size: 22px;")
        header.addWidget(icon_lbl)

        title_vbox = QVBoxLayout()
        title_lbl = QLabel("CyberGuard Potential Threat Detected")
        title_lbl.setStyleSheet("font-size: 15px; font-weight: bold; color: #F8FAFC;")
        subtitle_lbl = QLabel("Content matching known scam or phishing patterns was rendered on screen.")
        subtitle_lbl.setStyleSheet("font-size: 11px; color: #94A3B8;")
        title_vbox.addWidget(title_lbl)
        title_vbox.addWidget(subtitle_lbl)
        header.addLayout(title_vbox)
        header.addStretch()

        pill_lbl = QLabel(f" {severity} ({score}/100) ")
        pill_lbl.setStyleSheet(f"""
            background-color: {bg_accent};
            color: {accent_color};
            border: 1px solid {accent_color};
            border-radius: 6px;
            font-size: 12px;
            font-weight: bold;
            padding: 4px 6px;
        """)
        header.addWidget(pill_lbl)
        layout.addLayout(header)

        # Divider
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet("color: #334155;")
        layout.addWidget(divider)

        # Detected Categories
        cats_text = ", ".join(categories) if categories else "Suspicious Signals"
        cat_lbl = QLabel(f"<b>Categories:</b> {cats_text}")
        cat_lbl.setStyleSheet("font-size: 12px; color: #38BDF8;")
        cat_lbl.setWordWrap(True)
        layout.addWidget(cat_lbl)

        # Explanation box
        reasons_text = "\n• ".join(reasons[:3]) if reasons else "Multiple deceptive markers identified."
        reason_box = QLabel(f"• {reasons_text}")
        reason_box.setWordWrap(True)
        reason_box.setStyleSheet("""
            background-color: #1E293B;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 8px;
            font-size: 11px;
            color: #E2E8F0;
        """)
        layout.addWidget(reason_box)

        # Bottom Buttons
        btn_row = QHBoxLayout()
        privacy_note = QLabel("Local Analysis • No Actions Taken")
        privacy_note.setStyleSheet("font-size: 10px; color: #64748B;")
        btn_row.addWidget(privacy_note)
        btn_row.addStretch()

        details_btn = QPushButton("View Details")
        details_btn.clicked.connect(self._on_view_details)
        btn_row.addWidget(details_btn)

        dismiss_btn = QPushButton("Dismiss")
        dismiss_btn.setObjectName("actionBtn")
        dismiss_btn.clicked.connect(self.close)
        btn_row.addWidget(dismiss_btn)

        layout.addLayout(btn_row)

    def _on_view_details(self):
        self.view_details_requested.emit(self.threat_data)
        self.close()

