"""
CyberGuard Desktop - Settings & Preferences Dialog
Precision hardware/security instrument aesthetic configuration panel
matching Stitch Screen 6.
"""

from pathlib import Path
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QSpinBox, QDoubleSpinBox, QPushButton, QFileDialog,
    QMessageBox, QGroupBox, QListWidget, QListWidgetItem, QCheckBox,
    QFrame
)
from PySide6.QtCore import Qt
from config import APP_CONFIG, CyberGuardConfig


class SettingsDialog(QDialog):
    def __init__(self, parent=None, config: CyberGuardConfig = APP_CONFIG):
        super().__init__(parent)
        self.config = config
        self.setWindowTitle("CyberGuard // Settings & Configuration")
        self.setMinimumWidth(600)
        self.setModal(True)
        self._init_ui()
        self._load_values()

    def _init_ui(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #0B1120;
                color: #F8FAFC;
                font-family: 'Segoe UI', -apple-system, sans-serif;
            }
            QGroupBox {
                background-color: #131E32;
                border: 1px solid #1E293B;
                border-radius: 8px;
                margin-top: 14px;
                padding-top: 16px;
                font-size: 11px;
                font-weight: 800;
                letter-spacing: 0.5px;
                color: #38BDF8;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px;
                background-color: #131E32;
            }
            QLabel {
                color: #E2E8F0;
                font-size: 12px;
            }
            QLineEdit, QSpinBox, QDoubleSpinBox, QListWidget {
                background-color: #0B1120;
                border: 1px solid #1E293B;
                border-radius: 6px;
                color: #F8FAFC;
                padding: 6px 10px;
                font-size: 12px;
                font-family: 'Segoe UI', monospace;
            }
            QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {
                border: 1px solid #0EA5E9;
            }
            QPushButton {
                background-color: #1E293B;
                color: #F8FAFC;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 7px 16px;
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
            QCheckBox {
                color: #CBD5E1;
                font-size: 12px;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border: 1px solid #334155;
                border-radius: 4px;
                background-color: #0B1120;
            }
            QCheckBox::indicator:checked {
                background-color: #0EA5E9;
                border-color: #0EA5E9;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(22, 20, 22, 20)

        # Title bar
        title_row = QHBoxLayout()
        shield_icon = QLabel("⚙")
        shield_icon.setStyleSheet("font-size: 16px; color: #38BDF8;")
        title_row.addWidget(shield_icon)

        title = QLabel("CYBERGUARD // APPLICATION PREFERENCES")
        title.setStyleSheet("font-size: 13px; font-weight: 800; letter-spacing: 0.8px; color: #F8FAFC;")
        title_row.addWidget(title)
        title_row.addStretch()
        layout.addLayout(title_row)

        # 1. OCR Settings
        ocr_group = QGroupBox("SECTION 1: OCR & COMPUTER VISION ENGINE")
        ocr_layout = QVBoxLayout(ocr_group)
        ocr_layout.setContentsMargins(14, 14, 14, 14)
        ocr_layout.setSpacing(8)

        tess_lbl = QLabel("Tesseract Executable Binary Path:")
        ocr_layout.addWidget(tess_lbl)

        tess_row = QHBoxLayout()
        self.tess_path_input = QLineEdit()
        self.tess_browse_btn = QPushButton("Browse...")
        self.tess_browse_btn.clicked.connect(self._browse_tesseract)
        tess_row.addWidget(self.tess_path_input)
        tess_row.addWidget(self.tess_browse_btn)
        ocr_layout.addLayout(tess_row)

        self.tess_status_lbl = QLabel()
        ocr_layout.addWidget(self.tess_status_lbl)
        layout.addWidget(ocr_group)

        # 2. Monitoring Timing & Sensitivity
        mon_group = QGroupBox("SECTION 2: SCREEN SAMPLING & DIFFERENTIAL ANALYSIS")
        mon_layout = QVBoxLayout(mon_group)
        mon_layout.setContentsMargins(14, 14, 14, 14)
        mon_layout.setSpacing(10)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Frame Capture Interval (seconds):"))
        self.interval_spin = QDoubleSpinBox()
        self.interval_spin.setRange(1.0, 15.0)
        self.interval_spin.setSingleStep(0.5)
        row1.addWidget(self.interval_spin)
        mon_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Differential Change Sensitivity Threshold (%):"))
        self.diff_spin = QDoubleSpinBox()
        self.diff_spin.setRange(0.1, 10.0)
        self.diff_spin.setSingleStep(0.1)
        row2.addWidget(self.diff_spin)
        mon_layout.addLayout(row2)

        layout.addWidget(mon_group)

        # 3. Detection & Alerts
        alert_group = QGroupBox("SECTION 3: THREAT ALERTS & SYSTEM BEHAVIOR")
        alert_layout = QVBoxLayout(alert_group)
        alert_layout.setContentsMargins(14, 14, 14, 14)
        alert_layout.setSpacing(10)

        row_alert = QHBoxLayout()
        row_alert.addWidget(QLabel("Risk Trigger Alert Threshold (Score 0-100):"))
        self.alert_spin = QSpinBox()
        self.alert_spin.setRange(20, 95)
        row_alert.addWidget(self.alert_spin)
        alert_layout.addLayout(row_alert)

        self.alert_check = QCheckBox("Show floating overlay notification on high/critical threat detection")
        alert_layout.addWidget(self.alert_check)

        self.tray_close_check = QCheckBox("Minimize to Windows System Tray on window close (Default: Exit cleanly)")
        alert_layout.addWidget(self.tray_close_check)

        layout.addWidget(alert_group)

        # 4. Excluded Applications
        excl_group = QGroupBox("SECTION 4: PRIVACY FILTERING (WINDOW TITLE EXCLUSIONS)")
        excl_layout = QVBoxLayout(excl_group)
        excl_layout.setContentsMargins(14, 14, 14, 14)
        excl_layout.setSpacing(8)

        desc = QLabel("Displays matching these window titles will not be captured or analyzed:")
        desc.setStyleSheet("font-size: 11px; color: #94A3B8;")
        excl_layout.addWidget(desc)

        self.excl_list = QListWidget()
        self.excl_list.setFixedHeight(75)
        excl_layout.addWidget(self.excl_list)

        excl_btn_row = QHBoxLayout()
        self.excl_input = QLineEdit()
        self.excl_input.setPlaceholderText("e.g. PasswordSafe, Bitwarden, KeePass, Banking...")
        self.add_excl_btn = QPushButton("+ Add Keyword")
        self.add_excl_btn.clicked.connect(self._add_exclusion)
        self.del_excl_btn = QPushButton("Remove Selected")
        self.del_excl_btn.clicked.connect(self._remove_exclusion)
        excl_btn_row.addWidget(self.excl_input)
        excl_btn_row.addWidget(self.add_excl_btn)
        excl_btn_row.addWidget(self.del_excl_btn)
        excl_layout.addLayout(excl_btn_row)

        layout.addWidget(excl_group)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.cancel_btn)

        self.save_btn = QPushButton("Save Settings")
        self.save_btn.setObjectName("primaryBtn")
        self.save_btn.clicked.connect(self._save_settings)
        btn_layout.addWidget(self.save_btn)

        layout.addLayout(btn_layout)

    def _load_values(self):
        self.tess_path_input.setText(self.config.tesseract_cmd or "")
        self._update_tess_status(self.config.tesseract_cmd)
        self.tess_path_input.textChanged.connect(self._update_tess_status)

        self.interval_spin.setValue(self.config.capture_interval_sec)
        self.diff_spin.setValue(self.config.screen_diff_threshold * 100.0)
        self.alert_spin.setValue(self.config.alert_threshold)
        self.alert_check.setChecked(self.config.enable_alert_overlay)
        self.tray_close_check.setChecked(getattr(self.config, "minimize_to_tray_on_close", False))

        self.excl_list.clear()
        for item in self.config.excluded_window_titles:
            self.excl_list.addItem(item)

    def _update_tess_status(self, path_str: str):
        path = Path(path_str.strip())
        if path.is_file():
            self.tess_status_lbl.setText("✓ Tesseract OCR executable verified & operational.")
            self.tess_status_lbl.setStyleSheet("color: #10B981; font-size: 11px; font-weight: bold;")
        elif not path_str.strip():
            self.tess_status_lbl.setText("⚠ Tesseract not configured. Text extraction disabled.")
            self.tess_status_lbl.setStyleSheet("color: #EF4444; font-size: 11px;")
        else:
            self.tess_status_lbl.setText("⚠ Specified file path not found.")
            self.tess_status_lbl.setStyleSheet("color: #EF4444; font-size: 11px;")

    def _browse_tesseract(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Tesseract Executable", "C:\\Program Files", "Executable Files (*.exe)"
        )
        if file_path:
            self.tess_path_input.setText(file_path)

    def _add_exclusion(self):
        text = self.excl_input.text().strip()
        if text:
            self.excl_list.addItem(text)
            self.excl_input.clear()

    def _remove_exclusion(self):
        for item in self.excl_list.selectedItems():
            self.excl_list.takeItem(self.excl_list.row(item))

    def _save_settings(self):
        self.config.tesseract_cmd = self.tess_path_input.text().strip()
        self.config.capture_interval_sec = self.interval_spin.value()
        self.config.screen_diff_threshold = self.diff_spin.value() / 100.0
        self.config.alert_threshold = self.alert_spin.value()
        self.config.enable_alert_overlay = self.alert_check.isChecked()
        self.config.minimize_to_tray_on_close = self.tray_close_check.isChecked()

        exclusions = []
        for i in range(self.excl_list.count()):
            exclusions.append(self.excl_list.item(i).text())
        self.config.excluded_window_titles = exclusions

        self.config.save()
        self.accept()
