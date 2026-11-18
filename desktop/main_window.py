"""
CyberGuard Desktop - Main Application Window
Precision circular floating security instrument HUD built with PySide6 for Windows 11.
"""

from pathlib import Path
import math

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QGridLayout, QMessageBox, QApplication
)
from PySide6.QtCore import Qt, Signal, Slot, QTimer, QPoint, QRectF
from PySide6.QtGui import (
    QIcon, QPixmap, QPainter, QColor, QPen, QBrush,
    QRadialGradient, QLinearGradient, QFont, QPainterPath
)

from config import APP_CONFIG, PROJECT_ROOT
from desktop.settings import SettingsDialog
from desktop.threat_history import ThreatHistoryWidget, ThreatHistoryDialog
from desktop.alert_overlay import ThreatAlertOverlay
from desktop.tray import SystemTrayManager
from utils.logger import logger


class MainWindow(QMainWindow):
    """
    Main circular security HUD for CyberGuard Desktop.
    Features a floating 560x560 frameless circular instrument interface
    with concentric telemetry rings, radar sweep, and live risk metrics.
    """
    start_monitoring_requested = Signal()
    pause_monitoring_requested = Signal()
    stop_monitoring_requested = Signal()
    scan_now_requested = Signal()

    def __init__(self, config=APP_CONFIG, parent=None):
        super().__init__(parent)
        self.config = config
        self.setWindowTitle("CyberGuard Desktop - Screen Phishing & Fraud Guardian")

        # Circular frameless floating configuration
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setFixedSize(560, 560)

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
        self.current_risk_score = 0
        self.current_severity = "LOW"

        self.active_alert = None
        self._is_quitting = False
        self._drag_pos = None

        # Radar animation state
        self._radar_angle = 0
        self._radar_timer = QTimer(self)
        self._radar_timer.setInterval(40)  # ~25 FPS when active
        self._radar_timer.timeout.connect(self._on_radar_tick)

        # Threat history widget & dialog
        self.history_widget = ThreatHistoryWidget()
        self.history_widget.clear_history_requested.connect(self._on_clear_history)
        self.history_dialog = ThreatHistoryDialog(self.history_widget, self)

        self._init_ui()
        self._init_tray()
        self.update_monitoring_state(is_monitoring=False, is_paused=False)

    def _init_ui(self):
        # Global stylesheet for circular HUD child components
        self.setStyleSheet("""
            QWidget {
                color: #F8FAFC;
                font-family: 'Segoe UI', -apple-system, sans-serif;
            }
            QPushButton {
                background-color: #1E293B;
                color: #F8FAFC;
                border: 1px solid #334155;
                border-radius: 14px;
                padding: 6px 14px;
                font-size: 11px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: #334155;
            }
            QPushButton:disabled {
                background-color: #0F172A;
                color: #475569;
                border-color: #1E293B;
            }
            QPushButton#primaryBtn {
                background-color: #0EA5E9;
                color: #FFFFFF;
                border: 1px solid #38BDF8;
            }
            QPushButton#primaryBtn:hover {
                background-color: #0284C7;
            }
            QPushButton#pauseBtn {
                background-color: #F59E0B;
                color: #0F172A;
                border: 1px solid #FBBF24;
            }
            QPushButton#pauseBtn:hover {
                background-color: #D97706;
            }
            QPushButton#stopBtn {
                background-color: #EF4444;
                color: #FFFFFF;
                border: 1px solid #F87171;
            }
            QPushButton#stopBtn:hover {
                background-color: #DC2626;
            }
            QPushButton#scanBtn {
                background-color: #1E293B;
                color: #38BDF8;
                border: 1px solid #0EA5E9;
            }
            QPushButton#scanBtn:hover {
                background-color: #0EA5E9;
                color: #FFFFFF;
            }
            QPushButton#navBtn {
                background-color: #131E32;
                color: #94A3B8;
                border: 1px solid #1E293B;
                border-radius: 11px;
                padding: 4px 8px;
                font-size: 10px;
                font-weight: 600;
            }
            QPushButton#navBtn:hover {
                background-color: #1E293B;
                color: #F8FAFC;
            }
            QPushButton#windowCtrlBtn {
                background-color: #1E293B;
                color: #94A3B8;
                border: 1px solid #334155;
                border-radius: 10px;
                min-width: 20px;
                max-width: 20px;
                min-height: 20px;
                max-height: 20px;
                padding: 0px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton#windowCtrlBtn:hover {
                background-color: #EF4444;
                color: #FFFFFF;
                border-color: #EF4444;
            }
        """)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        # Main Layout inside circular boundary
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(60, 42, 60, 42)
        main_layout.setSpacing(8)

        # 1. Top Header Row (Window controls & Drag zone)
        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(6)

        shield_icon = QLabel("🛡")
        shield_icon.setStyleSheet("font-size: 13px; color: #0EA5E9;")
        top_row.addWidget(shield_icon)

        title_lbl = QLabel("CYBERGUARD")
        title_lbl.setStyleSheet("font-size: 11px; font-weight: 900; letter-spacing: 1.5px; color: #F8FAFC;")
        top_row.addWidget(title_lbl)

        version_pill = QLabel("v1.0")
        version_pill.setStyleSheet("font-size: 9px; font-weight: 700; color: #64748B; padding: 1px 4px;")
        top_row.addWidget(version_pill)

        top_row.addStretch()

        # History & Settings shortcuts
        self.history_btn = QPushButton("📋 History")
        self.history_btn.setObjectName("navBtn")
        self.history_btn.clicked.connect(self._open_history)
        top_row.addWidget(self.history_btn)

        self.settings_btn = QPushButton("⚙")
        self.settings_btn.setObjectName("navBtn")
        self.settings_btn.setToolTip("Configure OCR, Timing & Privacy Exclusions")
        self.settings_btn.clicked.connect(self._open_settings)
        top_row.addWidget(self.settings_btn)

        # Minimize & Close
        min_btn = QPushButton("—")
        min_btn.setObjectName("windowCtrlBtn")
        min_btn.setToolTip("Minimize to Taskbar")
        min_btn.clicked.connect(self.showMinimized)
        top_row.addWidget(min_btn)

        close_btn = QPushButton("✕")
        close_btn.setObjectName("windowCtrlBtn")
        close_btn.setToolTip("Exit CyberGuard")
        close_btn.clicked.connect(self.close)
        top_row.addWidget(close_btn)

        main_layout.addLayout(top_row)

        # 2. Upper Telemetry Row (Total Scans & Active Threats)
        upper_metrics = QHBoxLayout()
        upper_metrics.setContentsMargins(10, 8, 10, 4)

        # Total Scans
        scans_box = QVBoxLayout()
        scans_box.setSpacing(1)
        scans_title = QLabel("TOTAL SCANS")
        scans_title.setStyleSheet("font-size: 9px; font-weight: 800; letter-spacing: 0.8px; color: #64748B;")
        self.scans_val_lbl = QLabel("0")
        self.scans_val_lbl.setStyleSheet("font-size: 18px; font-weight: 900; color: #38BDF8; font-family: monospace;")
        scans_box.addWidget(scans_title)
        scans_box.addWidget(self.scans_val_lbl)
        upper_metrics.addLayout(scans_box)

        upper_metrics.addStretch()

        # Active Threats
        threats_box = QVBoxLayout()
        threats_box.setSpacing(1)
        threats_title = QLabel("ACTIVE THREATS")
        threats_title.setAlignment(Qt.AlignmentFlag.AlignRight)
        threats_title.setStyleSheet("font-size: 9px; font-weight: 800; letter-spacing: 0.8px; color: #64748B;")
        self.threats_val_lbl = QLabel("0")
        self.threats_val_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.threats_val_lbl.setStyleSheet("font-size: 18px; font-weight: 900; color: #FBBF24; font-family: monospace;")
        threats_box.addWidget(threats_title)
        threats_box.addWidget(self.threats_val_lbl)
        upper_metrics.addLayout(threats_box)

        main_layout.addLayout(upper_metrics)

        # 3. Central HUD Indicator Core
        center_core = QVBoxLayout()
        center_core.setSpacing(4)
        center_core.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Big Center Emblem / Radar Badge
        self.center_emblem = QLabel("🛡️")
        self.center_emblem.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.center_emblem.setStyleSheet("font-size: 34px;")
        center_core.addWidget(self.center_emblem)

        # Status Badge Pill
        self.status_badge = QLabel("IDLE • READY")
        self.status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_badge.setStyleSheet("""
            background-color: #131E32;
            color: #94A3B8;
            border: 1px solid #1E293B;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 0.8px;
            padding: 4px 14px;
        """)
        center_core.addWidget(self.status_badge)

        # Live Risk Score Readout
        self.risk_badge = QLabel("LOW RISK · 0/100")
        self.risk_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.risk_badge.setStyleSheet("""
            color: #34D399;
            font-size: 12px;
            font-weight: 900;
            letter-spacing: 0.5px;
            font-family: monospace;
            padding: 2px;
        """)
        center_core.addWidget(self.risk_badge)

        main_layout.addLayout(center_core)

        # 4. Lower Telemetry Row (High/Critical & Active Displays)
        lower_metrics = QHBoxLayout()
        lower_metrics.setContentsMargins(10, 4, 10, 8)

        # High/Critical
        crit_box = QVBoxLayout()
        crit_box.setSpacing(1)
        crit_title = QLabel("HIGH / CRITICAL")
        crit_title.setStyleSheet("font-size: 9px; font-weight: 800; letter-spacing: 0.8px; color: #64748B;")
        self.crit_val_lbl = QLabel("0")
        self.crit_val_lbl.setStyleSheet("font-size: 16px; font-weight: 900; color: #F87171; font-family: monospace;")
        crit_box.addWidget(crit_title)
        crit_box.addWidget(self.crit_val_lbl)
        lower_metrics.addLayout(crit_box)

        lower_metrics.addStretch()

        # Displays
        mon_box = QVBoxLayout()
        mon_box.setSpacing(1)
        mon_title = QLabel("ACTIVE DISPLAYS")
        mon_title.setAlignment(Qt.AlignmentFlag.AlignRight)
        mon_title.setStyleSheet("font-size: 9px; font-weight: 800; letter-spacing: 0.8px; color: #64748B;")
        self.mon_val_lbl = QLabel("1 Display")
        self.mon_val_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.mon_val_lbl.setStyleSheet("font-size: 15px; font-weight: 800; color: #A78BFA;")
        mon_box.addWidget(mon_title)
        mon_box.addWidget(self.mon_val_lbl)
        lower_metrics.addLayout(mon_box)

        main_layout.addLayout(lower_metrics)

        # 5. Primary Control Cluster (Start / Pause / Stop)
        control_row = QHBoxLayout()
        control_row.setSpacing(8)
        control_row.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.start_btn = QPushButton("▶  Start")
        self.start_btn.setObjectName("primaryBtn")
        self.start_btn.clicked.connect(self._on_start_clicked)
        control_row.addWidget(self.start_btn)

        self.pause_btn = QPushButton("⏸  Pause")
        self.pause_btn.setObjectName("pauseBtn")
        self.pause_btn.clicked.connect(self._on_pause_clicked)
        control_row.addWidget(self.pause_btn)

        self.stop_btn = QPushButton("⏹  Stop")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.clicked.connect(self._on_stop_clicked)
        control_row.addWidget(self.stop_btn)

        main_layout.addLayout(control_row)

        # 6. Secondary Tool Strip (Scan Now)
        tools_row = QHBoxLayout()
        tools_row.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.scan_now_btn = QPushButton("⚡  Scan Screen Now")
        self.scan_now_btn.setObjectName("scanBtn")
        self.scan_now_btn.clicked.connect(self._on_scan_now_clicked)
        tools_row.addWidget(self.scan_now_btn)

        main_layout.addLayout(tools_row)

        # 7. Subdued Privacy Footer
        footer_row = QHBoxLayout()
        footer_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.privacy_lbl = QLabel("🔒 100% Local Screen Analysis • 0 Cloud Data")
        self.privacy_lbl.setStyleSheet("font-size: 9px; font-weight: 600; color: #475569;")
        footer_row.addWidget(self.privacy_lbl)
        main_layout.addLayout(footer_row)

        # Backward compatibility stat containers
        self.stat_scans = {"value_lbl": self.scans_val_lbl}
        self.stat_threats = {"value_lbl": self.threats_val_lbl}
        self.stat_critical = {"value_lbl": self.crit_val_lbl}
        self.stat_monitors = {"value_lbl": self.mon_val_lbl}

    # -------------------------------------------------------------------------
    # QPainter Circular Background & HUD Telemetry Rings
    # -------------------------------------------------------------------------
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        center_x = self.width() / 2.0
        center_y = self.height() / 2.0
        outer_radius = 265.0

        # 1. Outer Dark Circular Disc Background
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#0B1120"))
        painter.drawEllipse(QPoint(int(center_x), int(center_y)), int(outer_radius), int(outer_radius))

        # 2. Outer Framing Ring
        pen_outer = QPen(QColor("#1E293B"), 2.0)
        painter.setPen(pen_outer)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(QPoint(int(center_x), int(center_y)), int(outer_radius - 2), int(outer_radius - 2))

        # 3. Dynamic Telemetry Status Arc / Ring
        if self.current_severity == "CRITICAL":
            accent_color = QColor("#EF4444")
        elif self.current_severity == "HIGH":
            accent_color = QColor("#F59E0B")
        elif self.current_severity in ("SUSPICIOUS", "MEDIUM"):
            accent_color = QColor("#0EA5E9")
        elif self.is_monitoring and not self.is_paused:
            accent_color = QColor("#10B981")
        elif self.is_paused:
            accent_color = QColor("#F59E0B")
        else:
            accent_color = QColor("#334155")

        pen_status = QPen(accent_color, 2.5)
        painter.setPen(pen_status)
        painter.drawEllipse(QPoint(int(center_x), int(center_y)), int(outer_radius - 8), int(outer_radius - 8))

        # 4. Secondary Concentric Reference Ring
        pen_inner = QPen(QColor("#131E32"), 1.5)
        painter.setPen(pen_inner)
        painter.drawEllipse(QPoint(int(center_x), int(center_y)), 195, 195)

        # 5. Central Radar Core Disc
        painter.setPen(QPen(QColor("#1E293B"), 1.5))
        painter.setBrush(QColor("#0F172A"))
        painter.drawEllipse(QPoint(int(center_x), int(center_y)), 100, 100)

        # 6. Active Radar Sweep Line (when monitoring)
        if self.is_monitoring and not self.is_paused:
            rad = math.radians(self._radar_angle)
            sweep_length = 98.0
            end_x = center_x + sweep_length * math.cos(rad)
            end_y = center_y + sweep_length * math.sin(rad)

            pen_sweep = QPen(accent_color, 1.8)
            pen_sweep.setColor(QColor(accent_color.red(), accent_color.green(), accent_color.blue(), 180))
            painter.setPen(pen_sweep)
            painter.drawLine(QPoint(int(center_x), int(center_y)), QPoint(int(end_x), int(end_y)))

        painter.end()

    def _on_radar_tick(self):
        self._radar_angle = (self._radar_angle + 4) % 360
        self.update()

    # -------------------------------------------------------------------------
    # Smooth Frameless Window Dragging
    # -------------------------------------------------------------------------
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton and self._drag_pos is not None:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_pos = None

    # -------------------------------------------------------------------------
    # Dialogs & Tray Integration
    # -------------------------------------------------------------------------
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

    def _open_history(self):
        self.history_dialog.show()
        self.history_dialog.raise_()
        self.history_dialog.activateWindow()

    def _open_settings(self):
        dialog = SettingsDialog(self, config=self.config)
        dialog.exec()

    # -------------------------------------------------------------------------
    # State Updates & Signals
    # -------------------------------------------------------------------------
    def update_monitoring_state(self, is_monitoring: bool, is_paused: bool):
        self.is_monitoring = is_monitoring
        self.is_paused = is_paused

        self.start_btn.setEnabled(not is_monitoring or is_paused)
        self.pause_btn.setEnabled(is_monitoring and not is_paused)
        self.stop_btn.setEnabled(is_monitoring)
        self.scan_now_btn.setEnabled(True)

        if not is_monitoring:
            self._radar_timer.stop()
            self.status_badge.setText("IDLE • READY")
            self.status_badge.setStyleSheet("""
                background-color: #131E32;
                color: #94A3B8;
                border: 1px solid #1E293B;
                border-radius: 12px;
                font-size: 10px;
                font-weight: 800;
                letter-spacing: 0.8px;
                padding: 4px 14px;
            """)
            self.start_btn.setText("▶  Start")
        elif is_paused:
            self._radar_timer.stop()
            self.status_badge.setText("MONITORING PAUSED")
            self.status_badge.setStyleSheet("""
                background-color: #451A03;
                color: #FBBF24;
                border: 1px solid #B45309;
                border-radius: 12px;
                font-size: 10px;
                font-weight: 800;
                letter-spacing: 0.8px;
                padding: 4px 14px;
            """)
            self.start_btn.setText("▶  Resume")
        else:
            self._radar_timer.start()
            self.status_badge.setText("MONITORING ACTIVE")
            self.status_badge.setStyleSheet("""
                background-color: #064E3B;
                color: #34D399;
                border: 1px solid #059669;
                border-radius: 12px;
                font-size: 10px;
                font-weight: 800;
                letter-spacing: 0.8px;
                padding: 4px 14px;
            """)
            self.start_btn.setText("▶  Active")

        self.tray.update_state(is_monitoring, is_paused)
        self.update()

    def set_ocr_missing_state(self, message: str):
        """Display clear setup guidance when Tesseract is missing."""
        self.status_badge.setText("OCR SETUP REQUIRED")
        self.status_badge.setStyleSheet("""
            background-color: #450A0A;
            color: #F87171;
            border: 1px solid #DC2626;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 0.8px;
            padding: 4px 14px;
        """)
        self.update()

    def update_risk_display(self, score: int, severity: str):
        self.current_risk_score = score
        self.current_severity = severity.upper()

        if self.current_severity == "CRITICAL":
            fg = "#EF4444"
        elif self.current_severity == "HIGH":
            fg = "#F97316"
        elif self.current_severity in ("SUSPICIOUS", "MEDIUM"):
            fg = "#FBBF24"
        else:
            fg = "#34D399"

        self.risk_badge.setText(f"{self.current_severity} · {score}/100")
        self.risk_badge.setStyleSheet(f"""
            color: {fg};
            font-size: 12px;
            font-weight: 900;
            letter-spacing: 0.5px;
            font-family: monospace;
            padding: 2px;
        """)
        self.update()

    def update_stats(self, scans: int, threats: int, high_critical: int, monitors: int):
        self.scan_count = scans
        self.threat_count = threats
        self.high_threat_count = high_critical
        self.monitor_count = monitors

        self.scans_val_lbl.setText(f"{scans:,}")
        self.threats_val_lbl.setText(str(threats))
        self.crit_val_lbl.setText(str(high_critical))
        display_str = f"{monitors} Display" if monitors == 1 else f"{monitors} Displays"
        self.mon_val_lbl.setText(display_str)
        self.history_btn.setText(f"📋 History ({threats})")

    def show_alert_overlay(self, threat_data: dict):
        if not self.config.enable_alert_overlay:
            return
        if self.active_alert:
            try:
                self.active_alert.close()
            except Exception:
                pass

        self.active_alert = ThreatAlertOverlay(threat_data, self)
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
        self.threats_val_lbl.setText("0")
        self.crit_val_lbl.setText("0")
        self.threat_count = 0
        self.high_threat_count = 0
        self.history_btn.setText("📋 History (0)")
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
                "CyberGuard circular HUD minimized. Screen guardian running in background.",
                timeout_ms=3000
            )
        else:
            self._is_quitting = True
            logger.info("Main HUD closed by user. Shutting down CyberGuard monitoring and application.")
            self._radar_timer.stop()
            self.stop_monitoring_requested.emit()
            self.tray.hide()
            try:
                self.history_dialog.close()
            except Exception:
                pass
            event.accept()
            app_inst = QApplication.instance()
            if app_inst:
                app_inst.quit()

    def quit_application(self):
        """Exit the application cleanly from tray or menu."""
        if self._is_quitting:
            return
        self._is_quitting = True
        logger.info("Application exit requested. Halting worker and cleaning up.")
        self._radar_timer.stop()
        self.stop_monitoring_requested.emit()
        self.tray.hide()
        try:
            self.history_dialog.close()
        except Exception:
            pass
        self.close()
        app_inst = QApplication.instance()
        if app_inst:
            app_inst.quit()
