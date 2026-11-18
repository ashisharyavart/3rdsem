"""
CyberGuard Desktop - Threat History & Event Inspector
Displays modular telemetry feed of detected screen security events matching
the precision hardware/security instrument aesthetic.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QDialog, QTextEdit, QMessageBox
)
from PySide6.QtCore import Qt, Signal


class ThreatDetailsDialog(QDialog):
    """Inspect forensic details of a specific detected threat event."""
    def __init__(self, item_data: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.setWindowTitle("CyberGuard // Threat Event Inspection")
        self.setMinimumSize(560, 420)
        self.setStyleSheet("""
            QDialog {
                background-color: #0B1120;
                color: #F8FAFC;
                font-family: 'Segoe UI', -apple-system, sans-serif;
            }
            QLabel {
                color: #E2E8F0;
                font-size: 13px;
            }
            QTextEdit {
                background-color: #131E32;
                border: 1px solid #1E293B;
                border-radius: 8px;
                color: #F8FAFC;
                font-family: 'Consolas', 'JetBrains Mono', monospace;
                font-size: 12px;
                padding: 10px;
            }
            QPushButton {
                background-color: #1E293B;
                color: #F8FAFC;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 8px 18px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #334155;
            }
            QPushButton#primaryBtn {
                background-color: #0EA5E9;
                color: #FFFFFF;
                border: none;
            }
            QPushButton#primaryBtn:hover {
                background-color: #0284C7;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(14)

        score = item_data.get("score", 0)
        severity = str(item_data.get("severity", "Unknown")).upper()
        if severity == "CRITICAL":
            sev_color = "#EF4444"
        elif severity == "HIGH":
            sev_color = "#F59E0B"
        elif severity in ("SUSPICIOUS", "MEDIUM"):
            sev_color = "#38BDF8"
        else:
            sev_color = "#10B981"

        header_row = QHBoxLayout()
        title_lbl = QLabel("FORENSIC THREAT EVENT INSPECTOR")
        title_lbl.setStyleSheet("font-size: 11px; font-weight: 800; letter-spacing: 1px; color: #94A3B8;")
        header_row.addWidget(title_lbl)
        header_row.addStretch()

        score_badge = QLabel(f"RISK {score}/100 · {severity}")
        score_badge.setStyleSheet(f"""
            background-color: #1E293B;
            color: {sev_color};
            border: 1px solid {sev_color};
            border-radius: 6px;
            font-size: 11px;
            font-weight: 800;
            padding: 4px 10px;
        """)
        header_row.addWidget(score_badge)
        layout.addLayout(header_row)

        # Meta grid
        info_frame = QFrame()
        info_frame.setStyleSheet("background-color: #131E32; border: 1px solid #1E293B; border-radius: 8px; padding: 10px;")
        info_layout = QVBoxLayout(info_frame)
        info_layout.setSpacing(6)

        ts = item_data.get("timestamp", "N/A")
        ts_lbl = QLabel(f"<b>Timestamp:</b> <span style='color: #38BDF8;'>{ts}</span>")
        info_layout.addWidget(ts_lbl)

        cats = item_data.get("categories", "None")
        if isinstance(cats, list):
            cats = ", ".join(cats)
        cat_lbl = QLabel(f"<b>Detected Patterns:</b> <span style='color: #F8FAFC;'>{cats}</span>")
        info_layout.addWidget(cat_lbl)

        domain_val = item_data.get("domain") or "No distinct domain extracted"
        dom_lbl = QLabel(f"<b>Target Domain / URL:</b> <span style='color: #FBBF24;'>{domain_val}</span>")
        info_layout.addWidget(dom_lbl)

        mon_id = item_data.get("monitor_id", 1)
        mon_lbl = QLabel(f"<b>Captured Display:</b> <span style='color: #94A3B8;'>Display {mon_id}</span>")
        info_layout.addWidget(mon_lbl)

        layout.addWidget(info_frame)

        layout.addWidget(QLabel("Heuristic Indicators & Extracted Context:"))
        details_box = QTextEdit()
        details_box.setReadOnly(True)
        explanation = item_data.get("explanation", "No detailed explanation.")
        if isinstance(explanation, list):
            explanation = "\n".join(f"• {e}" for e in explanation)
        details_box.setPlainText(str(explanation))
        layout.addWidget(details_box)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setObjectName("primaryBtn")
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)


class ThreatEventCard(QFrame):
    """Modular event card for detected threat in the timeline feed."""
    def __init__(self, item_data: Dict[str, Any], on_inspect, on_dismiss=None, parent=None):
        super().__init__(parent)
        self.item_data = item_data
        self.on_inspect = on_inspect
        self.on_dismiss = on_dismiss
        self._init_ui()

    def _init_ui(self):
        score = self.item_data.get("score", 0)
        severity = str(self.item_data.get("severity", "Low")).upper()

        if severity == "CRITICAL":
            border_color = "#EF4444"
            badge_bg = "#450A0A"
            badge_fg = "#EF4444"
        elif severity == "HIGH":
            border_color = "#F59E0B"
            badge_bg = "#451A03"
            badge_fg = "#F59E0B"
        elif severity in ("SUSPICIOUS", "MEDIUM"):
            border_color = "#0EA5E9"
            badge_bg = "#082F49"
            badge_fg = "#38BDF8"
        else:
            border_color = "#10B981"
            badge_bg = "#064E3B"
            badge_fg = "#34D399"

        self.setStyleSheet(f"""
            QFrame#cardFrame {{
                background-color: #131E32;
                border: 1px solid #1E293B;
                border-left: 3px solid {border_color};
                border-radius: 8px;
            }}
            QFrame#cardFrame:hover {{
                border-color: {border_color};
            }}
        """)
        self.setObjectName("cardFrame")

        card_layout = QVBoxLayout(self)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.setSpacing(6)

        # Top row: timestamp + risk score pill
        top_row = QHBoxLayout()
        ts_val = str(self.item_data.get("timestamp", ""))
        ts_lbl = QLabel(f"⏱ {ts_val}")
        ts_lbl.setStyleSheet("font-size: 11px; font-family: monospace; color: #94A3B8;")
        top_row.addWidget(ts_lbl)

        top_row.addStretch()

        score_pill = QLabel(f"[ {score}/100 · {severity} ]")
        score_pill.setStyleSheet(f"""
            background-color: {badge_bg};
            color: {badge_fg};
            border: 1px solid {border_color};
            border-radius: 4px;
            font-size: 10px;
            font-weight: 800;
            padding: 2px 8px;
            font-family: monospace;
        """)
        top_row.addWidget(score_pill)
        card_layout.addLayout(top_row)

        # Categories title
        cats = self.item_data.get("categories", "Suspicious Activity")
        if isinstance(cats, list):
            cats = " & ".join(cats) if cats else "Suspicious Screen Content"
        cat_title = QLabel(str(cats))
        cat_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #F8FAFC;")
        card_layout.addWidget(cat_title)

        # Snippet / domain
        domain = self.item_data.get("domain")
        expl = self.item_data.get("explanation", "")
        if isinstance(expl, list):
            expl = "; ".join(expl)
        first_line = expl.split("\n")[0] if expl else "Heuristic pattern detected."

        if domain:
            context_text = f"<span style='color: #FBBF24;'>URL: {domain}</span> — {first_line}"
        else:
            context_text = first_line

        context_lbl = QLabel(context_text)
        context_lbl.setWordWrap(True)
        context_lbl.setStyleSheet("font-size: 11px; color: #94A3B8; line-height: 1.3;")
        card_layout.addWidget(context_lbl)

        # Action row
        action_row = QHBoxLayout()
        action_row.addStretch()

        inspect_btn = QPushButton("Details")
        inspect_btn.setStyleSheet("""
            QPushButton {
                background-color: #1E293B;
                color: #38BDF8;
                border: 1px solid #334155;
                border-radius: 4px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #0EA5E9;
                color: #FFFFFF;
                border-color: #0EA5E9;
            }
        """)
        inspect_btn.clicked.connect(lambda: self.on_inspect(self.item_data))
        action_row.addWidget(inspect_btn)

        if self.on_dismiss:
            dismiss_btn = QPushButton("Dismiss")
            dismiss_btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    color: #64748B;
                    border: none;
                    padding: 3px 8px;
                    font-size: 11px;
                }
                QPushButton:hover {
                    color: #EF4444;
                }
            """)
            dismiss_btn.clicked.connect(lambda: self.on_dismiss(self))
            action_row.addWidget(dismiss_btn)

        card_layout.addLayout(action_row)


class ThreatHistoryWidget(QWidget):
    """
    Modular threat event feed widget displaying timeline cards, severity filtering,
    calm empty states, and inspection dialogs.
    """
    threat_selected = Signal(dict)
    clear_history_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.data_rows: List[Dict[str, Any]] = []
        self.active_filter = "ALL"
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # Header bar
        header_bar = QHBoxLayout()
        title_lbl = QLabel("THREAT HISTORY & FORENSICS")
        title_lbl.setStyleSheet("font-size: 12px; font-weight: 800; letter-spacing: 0.8px; color: #94A3B8;")
        header_bar.addWidget(title_lbl)

        self.count_badge = QLabel("0 EVENTS")
        self.count_badge.setStyleSheet("""
            background-color: #1E293B;
            color: #38BDF8;
            border: 1px solid #334155;
            border-radius: 10px;
            font-size: 10px;
            font-weight: bold;
            padding: 2px 8px;
        """)
        header_bar.addWidget(self.count_badge)

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
                font-weight: 500;
            }
            QPushButton:hover {
                color: #EF4444;
                border-color: #EF4444;
            }
        """)
        self.clear_btn.clicked.connect(self._on_clear_clicked)
        header_bar.addWidget(self.clear_btn)
        layout.addLayout(header_bar)

        # Filter Pills Strip
        filter_strip = QHBoxLayout()
        filter_strip.setSpacing(6)
        self.filter_buttons = {}

        filters = [("ALL", "All"), ("CRITICAL", "Critical"), ("HIGH", "High"), ("SUSPICIOUS", "Medium"), ("LOW", "Low")]
        for key, label in filters:
            btn = QPushButton(label)
            btn.setCheckable(True)
            if key == "ALL":
                btn.setChecked(True)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #0F172A;
                    color: #94A3B8;
                    border: 1px solid #1E293B;
                    border-radius: 12px;
                    padding: 3px 10px;
                    font-size: 11px;
                    font-weight: 600;
                }
                QPushButton:checked {
                    background-color: #0EA5E9;
                    color: #FFFFFF;
                    border-color: #0EA5E9;
                }
                QPushButton:hover:!checked {
                    background-color: #1E293B;
                    color: #F8FAFC;
                }
            """)
            btn.clicked.connect(lambda checked, k=key: self._set_filter(k))
            self.filter_buttons[key] = btn
            filter_strip.addWidget(btn)

        filter_strip.addStretch()
        layout.addLayout(filter_strip)

        # Scroll Area for Event Cards
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("""
            QScrollArea {
                border: 1px solid #1E293B;
                border-radius: 8px;
                background-color: #0B1120;
            }
            QScrollBar:vertical {
                background: #0B1120;
                width: 8px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background: #1E293B;
                min-height: 20px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: #334155;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)

        self.cards_container = QWidget()
        self.cards_layout = QVBoxLayout(self.cards_container)
        self.cards_layout.setContentsMargins(8, 8, 8, 8)
        self.cards_layout.setSpacing(8)
        self.cards_layout.addStretch()
        self.scroll_area.setWidget(self.cards_container)

        layout.addWidget(self.scroll_area, stretch=1)

        # Re-render initial empty state
        self._refresh_cards_view()

    def _set_filter(self, filter_key: str):
        self.active_filter = filter_key
        for k, btn in self.filter_buttons.items():
            btn.setChecked(k == filter_key)
        self._refresh_cards_view()

    def _refresh_cards_view(self):
        # Clear existing card widgets
        while self.cards_layout.count() > 0:
            child = self.cards_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        # Filter items
        filtered_items = []
        for item in self.data_rows:
            sev = str(item.get("severity", "Low")).upper()
            if self.active_filter == "ALL":
                filtered_items.append(item)
            elif self.active_filter == "CRITICAL" and sev == "CRITICAL":
                filtered_items.append(item)
            elif self.active_filter == "HIGH" and sev == "HIGH":
                filtered_items.append(item)
            elif self.active_filter in ("SUSPICIOUS", "MEDIUM") and sev in ("SUSPICIOUS", "MEDIUM"):
                filtered_items.append(item)
            elif self.active_filter == "LOW" and sev == "LOW":
                filtered_items.append(item)

        self.count_badge.setText(f"{len(self.data_rows)} EVENTS")

        if not filtered_items:
            empty_frame = QFrame()
            empty_frame.setStyleSheet("background: transparent; padding: 40px 20px;")
            empty_layout = QVBoxLayout(empty_frame)
            empty_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_layout.setSpacing(8)

            icon_lbl = QLabel("🛡️")
            icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_lbl.setStyleSheet("font-size: 32px;")
            empty_layout.addWidget(icon_lbl)

            all_clear_lbl = QLabel("ALL CLEAR — NO THREATS RECORDED")
            all_clear_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            all_clear_lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #10B981; letter-spacing: 0.5px;")
            empty_layout.addWidget(all_clear_lbl)

            sub_lbl = QLabel("Screen monitoring and OCR telemetry are actively scanning for phishing & scams.")
            sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sub_lbl.setStyleSheet("font-size: 11px; color: #64748B;")
            empty_layout.addWidget(sub_lbl)

            self.cards_layout.addWidget(empty_frame)
        else:
            for item in filtered_items:
                card = ThreatEventCard(
                    item_data=item,
                    on_inspect=self._inspect_item,
                    on_dismiss=self._dismiss_card
                )
                self.cards_layout.addWidget(card)

        self.cards_layout.addStretch()

    def _inspect_item(self, item_data: dict):
        self.threat_selected.emit(item_data)
        dialog = ThreatDetailsDialog(item_data, self)
        dialog.exec()

    def _dismiss_card(self, card_widget: ThreatEventCard):
        if card_widget.item_data in self.data_rows:
            self.data_rows.remove(card_widget.item_data)
            self._refresh_cards_view()

    def set_threats(self, threats: List[Dict[str, Any]]):
        self.data_rows = list(threats)
        self._refresh_cards_view()

    def add_threat(self, threat: Dict[str, Any]):
        self.data_rows.insert(0, threat)
        if len(self.data_rows) > 300:
            self.data_rows = self.data_rows[:300]
        self._refresh_cards_view()

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


class ThreatHistoryDialog(QDialog):
    """
    Dedicated floating utility window for Threat History & Forensics Inspector,
    matching Stitch Screen 5.
    """
    def __init__(self, history_widget: ThreatHistoryWidget, parent=None):
        super().__init__(parent)
        self.setWindowTitle("CyberGuard // Threat History & Event Inspector")
        self.resize(640, 720)
        self.setMinimumSize(540, 500)
        self.setStyleSheet("""
            QDialog {
                background-color: #0B1120;
                color: #F8FAFC;
                font-family: 'Segoe UI', -apple-system, sans-serif;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        # Header
        top_header = QHBoxLayout()
        shield_icon = QLabel("🛡")
        shield_icon.setStyleSheet("font-size: 16px;")
        top_header.addWidget(shield_icon)

        title = QLabel("CYBERGUARD // THREAT HISTORY & EVENT INSPECTOR")
        title.setStyleSheet("font-size: 13px; font-weight: 800; letter-spacing: 0.8px; color: #F8FAFC;")
        top_header.addWidget(title)
        top_header.addStretch()

        close_btn = QPushButton("✕")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #1E293B;
                color: #94A3B8;
                border: 1px solid #334155;
                border-radius: 12px;
                min-width: 24px;
                max-width: 24px;
                min-height: 24px;
                max-height: 24px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #EF4444;
                color: #FFFFFF;
                border-color: #EF4444;
            }
        """)
        close_btn.clicked.connect(self.accept)
        top_header.addWidget(close_btn)
        layout.addLayout(top_header)

        # Embed the ThreatHistoryWidget
        layout.addWidget(history_widget, stretch=1)
