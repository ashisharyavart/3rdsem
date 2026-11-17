"""
CyberGuard Desktop - System Tray Integration
Manages background operation, tray menu actions, and notifications.
"""

from pathlib import Path
from PySide6.QtWidgets import QSystemTrayIcon, QMenu
from PySide6.QtGui import QIcon, QAction
from PySide6.QtCore import Signal, QObject

from config import PROJECT_ROOT


class SystemTrayManager(QObject):
    """
    Manages the Windows System Tray Icon and its context menu.
    """
    open_requested = Signal()
    start_requested = Signal()
    pause_requested = Signal()
    stop_requested = Signal()
    exit_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.tray_icon = QSystemTrayIcon(parent)

        icon_path = PROJECT_ROOT / "assets" / "icons" / "shield_32.png"
        if not icon_path.exists():
            icon_path = PROJECT_ROOT / "assets" / "icons" / "shield.png"

        self.icon = QIcon(str(icon_path))
        self.tray_icon.setIcon(self.icon)
        self.tray_icon.setToolTip("CyberGuard Desktop - Screen Phishing & Fraud Guardian")

        self._create_menu()
        self.tray_icon.activated.connect(self._on_tray_activated)

    def _create_menu(self):
        self.menu = QMenu()

        self.action_open = QAction("Open CyberGuard", self.menu)
        self.action_open.triggered.connect(self.open_requested.emit)
        self.menu.addAction(self.action_open)

        self.menu.addSeparator()

        self.action_start = QAction("Start Monitoring", self.menu)
        self.action_start.triggered.connect(self.start_requested.emit)
        self.menu.addAction(self.action_start)

        self.action_pause = QAction("Pause Monitoring", self.menu)
        self.action_pause.triggered.connect(self.pause_requested.emit)
        self.menu.addAction(self.action_pause)

        self.action_stop = QAction("Stop Monitoring", self.menu)
        self.action_stop.triggered.connect(self.stop_requested.emit)
        self.menu.addAction(self.action_stop)

        self.menu.addSeparator()

        self.action_exit = QAction("Exit CyberGuard", self.menu)
        self.action_exit.triggered.connect(self.exit_requested.emit)
        self.menu.addAction(self.action_exit)

        self.tray_icon.setContextMenu(self.menu)

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.open_requested.emit()

    def show(self):
        self.tray_icon.show()

    def hide(self):
        self.tray_icon.hide()

    def show_message(self, title: str, message: str, icon=QSystemTrayIcon.MessageIcon.Information, timeout_ms: int = 5000):
        if self.tray_icon.isVisible():
            self.tray_icon.showMessage(title, message, icon, timeout_ms)

    def update_state(self, is_monitoring: bool, is_paused: bool):
        """Update enabled states of menu actions based on monitoring state."""
        self.action_start.setEnabled(not is_monitoring or is_paused)
        self.action_pause.setEnabled(is_monitoring and not is_paused)
        self.action_stop.setEnabled(is_monitoring)

