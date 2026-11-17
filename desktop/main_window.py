"""
CyberGuard Desktop - Main Application Window
Modern Windows 11 desktop GUI built with PySide6.
"""

from pathlib import Path
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QGridLayout, QMessageBox
)
from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtGui import QIcon, QPixmap

from config import APP_CONFIG, PROJECT_ROOT
from desktop.settings import SettingsDialog
from desktop.threat_history import ThreatHistoryWidget
from desktop.alert_overlay import ThreatAlertOverlay
from desktop.tray import SystemTrayManager
from utils.logger import logger


class MainWindow(QMainWindow):
    """
    Main application interface for CyberGuard Desktop.
    """
    start_monitoring_requested = Signal()
    pause_monitoring_requested = Signal()
    stop_monitoring_requested = Signal()
    scan_now_requested = Signal()

    def __init__(self, config=APP_CONFIG, parent=None):
        super().__init__(parent)
        self.config = config
        self.setWindowTitle("CyberGuard Desktop - Screen Phishing & Fraud Guardian")
        self.resize(1000, 700)
        self.setMinimumSize(850, 580)

        # Set App Icon
        icon_path = PROJECT_ROOT / "assets" / "icons" / "shield.png"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        # State tracking
        self.is_monitoring = False
        self.is_paused = False
        self.scan_count = 0
        self.threat_count = 0
        self.high_threat_count = 0
        self.monitor_count = 1

        self.active_alert = None
        self._is_quitting = False

        self._init_ui()
        self._init_tray()
        self.update_monitoring_state(is_monitoring=False, is_paused=False)

    def _init_ui(self):
        # Window & widget styles
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0B1120;
                color: #F8FAFC;
                font-family: 'Segoe UI', -apple-system, sans-serif;
            }
            QWidget {
                color: #F8FAFC;
            }
            QFrame#card {
                background-color: #1E293B;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 12px;
            }
            QFrame#topNav {
                background-color: #0F172A;
                border-bottom: 1px solid #1E293B;
                padding: 8px 16px;
            }
            QPushButton {
                background-color: #1E293B;
                color: #F8FAFC;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
                font-weight: 500;
            }
            QPushButton:hover {
                background-color: #334155;
            }
            QPushButton:disabled {
                background-color: #131D2D;
                color: #475569;
                border-color: #1E293B;
            }
            QPushButton#primaryBtn {
                background-color: #0EA5E9;
                color: #FFFFFF;
                font-weight: bold;
                border: none;
            }
            QPushButton#primaryBtn:hover {
                background-color: #0284C7;
            }
            QPushButton#pauseBtn {
                background-color: #F59E0B;
                color: #0F172A;
                font-weight: bold;
                border: none;
            }
            QPushButton#pauseBtn:hover {
                background-color: #D97706;
            }
            QPushButton#stopBtn {
                background-color: #EF4444;
                color: #FFFFFF;
                font-weight: bold;
                border: none;
            }
            QPushButton#stopBtn:hover {
                background-color: #DC2626;
            }
            QPushButton#scanBtn {
                background-color: #3B82F6;
                color: #FFFFFF;
                font-weight: 600;
                border: none;
            }
            QPushButton#scanBtn:hover {
                background-color: #2563EB;
            }
        """)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. Top Navigation Bar
        nav_frame = QFrame()
        nav_frame.setObjectName("topNav")
        nav_layout = QHBoxLayout(nav_frame)
        nav_layout.setContentsMargins(16, 12, 16, 12)

        # App Logo & Titles
        logo_lbl = QLabel()
        icon_path = PROJECT_ROOT / "assets" / "icons" / "shield_32.png"
        if icon_path.exists():
            logo_lbl.setPixmap(QPixmap(str(icon_path)))
        nav_layout.addWidget(logo_lbl)

        title_vbox = QVBoxLayout()
        title_vbox.setSpacing(1)
        app_title = QLabel("CYBERGUARD DESKTOP")
        app_title.setStyleSheet("font-size: 16px; font-weight: 800; letter-spacing: 0.5px; color: #F8FAFC;")
        app_sub = QLabel("Autonomous Screen Phishing & Social Engineering Guardian")
        app_sub.setStyleSheet("font-size: 11px; color: #94A3B8;")
        title_vbox.addWidget(app_title)
        title_vbox.addWidget(app_sub)
        nav_layout.addLayout(title_vbox)

        nav_layout.addStretch()

        # Monitoring Status Badge
        self.status_badge = QLabel("IDLE • READY")
        self.status_badge.setStyleSheet("""
            background-color: #1E293B;
            color: #94A3B8;
            border: 1px solid #334155;
            border-radius: 14px;
            font-size: 11px;
            font-weight: 700;
            padding: 5px 14px;
        """)
        nav_layout.addWidget(self.status_badge)

        # Settings button
        self.settings_btn = QPushButton("⚙ Settings")
        self.settings_btn.clicked.connect(self._open_settings)
        nav_layout.addWidget(self.settings_btn)

        main_layout.addWidget(nav_frame)

        # 2. Main Content Body
        body_widget = QWidget()
        body_layout = QVBoxLayout(body_widget)
        body_layout.setContentsMargins(20, 16, 20, 16)
        body_layout.setSpacing(16)

        # Action Control Bar
        control_bar = QHBoxLayout()
        control_bar.setSpacing(10)

        self.start_btn = QPushButton("▶  Start Monitoring")
        self.start_btn.setObjectName("primaryBtn")
        self.start_btn.clicked.connect(self._on_start_clicked)
        control_bar.addWidget(self.start_btn)

        self.pause_btn = QPushButton("⏸  Pause")
        self.pause_btn.setObjectName("pauseBtn")
        self.pause_btn.clicked.connect(self._on_pause_clicked)
        control_bar.addWidget(self.pause_btn)

        self.stop_btn = QPushButton("⏹  Stop")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.clicked.connect(self._on_stop_clicked)
        control_bar.addWidget(self.stop_btn)

        self.scan_now_btn = QPushButton("🔍  Scan Now")
        self.scan_now_btn.setObjectName("scanBtn")
        self.scan_now_btn.clicked.connect(self._on_scan_now_clicked)
        control_bar.addWidget(self.scan_now_btn)

        control_bar.addStretch()

        # Current Risk Badge
        risk_container = QHBoxLayout()
        risk_lbl_title = QLabel("CURRENT SCREEN RISK:")
        risk_lbl_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #94A3B8;")
        risk_container.addWidget(risk_lbl_title)

        self.risk_badge = QLabel("LOW RISK (0/100)")
        self.risk_badge.setStyleSheet("""
            background-color: #064E3B;
            color: #34D399;
            border: 1px solid #059669;
            border-radius: 6px;
            font-size: 12px;
            font-weight: bold;
            padding: 4px 10px;
        """)
        risk_container.addWidget(self.risk_badge)
        control_bar.addLayout(risk_container)

        body_layout.addLayout(control_bar)

        # Stat Cards Grid
        stats_grid = QGridLayout()
        stats_grid.setSpacing(12)

        self.stat_scans = self._create_stat_card("TOTAL SCANS", "0", "#38BDF8")
        self.stat_threats = self._create_stat_card("ACTIVE THREATS", "0", "#FBBF24")
        self.stat_critical = self._create_stat_card("HIGH / CRITICAL", "0", "#F87171")
        self.stat_monitors = self._create_stat_card("ACTIVE DISPLAYS", "1 Display", "#A78BFA")

        stats_grid.addWidget(self.stat_scans["card"], 0, 0)
        stats_grid.addWidget(self.stat_threats["card"], 0, 1)
        stats_grid.addWidget(self.stat_critical["card"], 0, 2)
        stats_grid.addWidget(self.stat_monitors["card"], 0, 3)

        body_layout.addLayout(stats_grid)

        # Threat History Table Widget
        self.history_widget = ThreatHistoryWidget()
        self.history_widget.clear_history_requested.connect(self._on_clear_history)
        body_layout.addWidget(self.history_widget, stretch=1)

        # Bottom Privacy & Status Footer
        footer = QHBoxLayout()
        self.privacy_lbl = QLabel(
            "🔒 <b>Privacy Status:</b> 100% Local Analysis • No Screen Captures Saved • Zero Cloud Transmission"
        )
        self.privacy_lbl.setStyleSheet("font-size: 11px; color: #64748B;")
        footer.addWidget(self.privacy_lbl)

        footer.addStretch()

        self.displays_lbl = QLabel("Multi-Display Protection: Enabled")
        self.displays_lbl.setStyleSheet("font-size: 11px; color: #38BDF8;")
        footer.addWidget(self.displays_lbl)

        body_layout.addLayout(footer)

        main_layout.addWidget(body_widget)

    def _create_stat_card(self, title: str, value: str, value_color: str) -> dict:
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        t_lbl = QLabel(title)
        t_lbl.setStyleSheet("font-size: 10px; font-weight: bold; color: #94A3B8; letter-spacing: 0.5px;")

        v_lbl = QLabel(value)
        v_lbl.setStyleSheet(f"font-size: 20px; font-weight: 800; color: {value_color};")

        layout.addWidget(t_lbl)
        layout.addWidget(v_lbl)
        return {"card": card, "value_lbl": v_lbl}

    def _init_tray(self):
        self.tray = SystemTrayManager(self)
        self.tray.open_requested.connect(self.show_and_activate)
        self.tray.start_requested.connect(self._on_start_clicked)
        self.tray.pause_requested.connect(self._on_pause_clicked)
        self.tray.stop_requested.connect(self._on_stop_clicked)
        self.tray.exit_requested.connect(self.quit_application)
        self.tray.show()

    def show_and_activate(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def _open_settings(self):
        dialog = SettingsDialog(self, config=self.config)
        dialog.exec()

    # Monitoring State Updates
    def update_monitoring_state(self, is_monitoring: bool, is_paused: bool):
        self.is_monitoring = is_monitoring
        self.is_paused = is_paused

        self.start_btn.setEnabled(not is_monitoring or is_paused)
        self.pause_btn.setEnabled(is_monitoring and not is_paused)
        self.stop_btn.setEnabled(is_monitoring)
        self.scan_now_btn.setEnabled(True)

        if not is_monitoring:
            self.status_badge.setText("IDLE • READY")
            self.status_badge.setStyleSheet("""
                background-color: #1E293B;
                color: #94A3B8;
                border: 1px solid #334155;
                border-radius: 14px;
                font-size: 11px;
                font-weight: 700;
                padding: 5px 14px;
            """)
        elif is_paused:
            self.status_badge.setText("PAUSED")
            self.status_badge.setStyleSheet("""
                background-color: #451A03;
                color: #FBBF24;
                border: 1px solid #B45309;
                border-radius: 14px;
                font-size: 11px;
                font-weight: 700;
                padding: 5px 14px;
            """)
        else:
            self.status_badge.setText("MONITORING ACTIVE")
            self.status_badge.setStyleSheet("""
                background-color: #064E3B;
                color: #34D399;
                border: 1px solid #059669;
                border-radius: 14px;
                font-size: 11px;
                font-weight: 700;
                padding: 5px 14px;
            """)

        self.tray.update_state(is_monitoring, is_paused)

    def set_ocr_missing_state(self, message: str):
        """Display clear setup guidance when Tesseract is missing."""
        self.status_badge.setText("OCR SETUP REQUIRED")
        self.status_badge.setStyleSheet("""
            background-color: #450A0A;
            color: #F87171;
            border: 1px solid #DC2626;
            border-radius: 14px;
            font-size: 11px;
            font-weight: 700;
            padding: 5px 14px;
        """)

    def update_risk_display(self, score: int, severity: str):
        sev_upper = severity.upper()
        if sev_upper == "CRITICAL":
            style = "background-color: #450A0A; color: #EF4444; border: 1px solid #DC2626;"
        elif sev_upper == "HIGH":
            style = "background-color: #431407; color: #F97316; border: 1px solid #EA580C;"
        elif sev_upper == "SUSPICIOUS":
            style = "background-color: #422006; color: #FBBF24; border: 1px solid #D97706;"
        else:
            style = "background-color: #064E3B; color: #34D399; border: 1px solid #059669;"

        self.risk_badge.setText(f"{sev_upper} ({score}/100)")
        self.risk_badge.setStyleSheet(f"""
            {style}
            border-radius: 6px;
            font-size: 12px;
            font-weight: bold;
            padding: 4px 10px;
        """)

    def update_stats(self, scans: int, threats: int, high_critical: int, monitors: int):
        self.scan_count = scans
        self.threat_count = threats
        self.high_threat_count = high_critical
        self.monitor_count = monitors

        self.stat_scans["value_lbl"].setText(str(scans))
        self.stat_threats["value_lbl"].setText(str(threats))
        self.stat_critical["value_lbl"].setText(str(high_critical))
        display_str = f"{monitors} Display" if monitors == 1 else f"{monitors} Displays"
        self.stat_monitors["value_lbl"].setText(display_str)

    def show_alert_overlay(self, threat_data: dict):
        if not self.config.enable_alert_overlay:
            return
        if self.active_alert:
            try:
                self.active_alert.close()
            except Exception:
                pass

        self.active_alert = ThreatAlertOverlay(threat_data, self)
        # Position overlay at bottom-right above taskbar
        screen_geo = self.screen().geometry()
        x = screen_geo.width() - self.active_alert.width() - 25
        y = screen_geo.height() - self.active_alert.height() - 60
        self.active_alert.move(x, y)
        self.active_alert.show()

    # Slot handlers
    def _on_start_clicked(self):
        logger.info("Start monitoring requested by user.")
        self.start_monitoring_requested.emit()

    def _on_pause_clicked(self):
        logger.info("Pause monitoring requested by user.")
        self.pause_monitoring_requested.emit()

    def _on_stop_clicked(self):
        logger.info("Stop monitoring requested by user.")
        self.stop_monitoring_requested.emit()

    def _on_scan_now_clicked(self):
        logger.info("Immediate scan requested by user.")
        self.scan_now_requested.emit()

    def _on_clear_history(self):
        self.stat_threats["value_lbl"].setText("0")
        self.stat_critical["value_lbl"].setText("0")
        self.threat_count = 0
        self.high_threat_count = 0
        self._is_quitting = False

    def closeEvent(self, event):
        """Handle window close event with proper worker shutdown and cleanup."""
        if self._is_quitting:
            event.accept()
            return

        if self.config.minimize_to_tray_on_close and self.is_monitoring:
            event.ignore()
            self.hide()
            self.tray.show_message(
                "CyberGuard Active",
                "CyberGuard is continuing to monitor your screens in the background.",
                timeout_ms=3000
            )
        else:
            self._is_quitting = True
            logger.info("Main window closed by user. Shutting down CyberGuard monitoring and application.")
            self.stop_monitoring_requested.emit()
            self.tray.hide()
            event.accept()
            # Ensure QApplication event loop terminates
            from PySide6.QtWidgets import QApplication
            app_inst = QApplication.instance()
            if app_inst:
                app_inst.quit()

    def quit_application(self):
        """Exit the application cleanly from tray or menu."""
        if self._is_quitting:
            return
        self._is_quitting = True
        logger.info("Application exit requested. Halting worker and cleaning up.")
        self.stop_monitoring_requested.emit()
        self.tray.hide()
        self.close()
        from PySide6.QtWidgets import QApplication
        app_inst = QApplication.instance()
        if app_inst:
            app_inst.quit()

