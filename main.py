"""
SecureCrypt — Main Entry Point & PyQt6 GUI

Tabs
────
1. Dashboard       – status overview, quick actions
2. Tunnel Server   – start/stop server, view sessions
3. Tunnel Client   – connect to remote server
4. Proxy Server    – start/stop HTTP/S proxy
5. Crypto Tools    – encrypt/decrypt/hash playground
6. Key Manager     – generate, list, delete keys
7. Logs            – live scrolling log output

Every network service runs in background threads; the GUI stays
responsive via Qt signals.
"""

import sys
import os
import time
import logging
import threading
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QSpinBox, QFileDialog, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QStatusBar, QCheckBox, QPlainTextEdit,
    QSizePolicy,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor, QIcon, QTextCursor

# ── SecureCrypt imports ──────────────────────────────────────────
from config.settings import Settings

from core.crypto_engine import AESCrypto, RSACrypto, ECCCrypto, HashCrypto

from utils.random_gen     import SecureRandom
from utils.key_manager    import KeyManager
from utils.secure_storage import SecureStorage
from utils.framing        import Framing, MessageType

from traffic.handshake       import HandshakeProtocol
from traffic.session_manager import Session, SessionManager
from traffic.tunnel_server   import TunnelServer, TunnelClient
from traffic.proxy_client    import ProxyServer

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Qt Log Handler — routes Python logging into the GUI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class QtLogSignal(QObject):
    """Bridge: Python logging → Qt signal."""
    log_message = pyqtSignal(str)


class QtLogHandler(logging.Handler):
    """Logging handler that emits a Qt signal for each record."""

    def __init__(self):
        super().__init__()
        self.signal_emitter = QtLogSignal()
        fmt = logging.Formatter(
            "[%(asctime)s] [%(levelname)-8s] %(name)-28s — %(message)s",
            datefmt="%H:%M:%S",
        )
        self.setFormatter(fmt)

    def emit(self, record):
        msg = self.format(record)
        self.signal_emitter.log_message.emit(msg)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Signal Bridge — thread-safe callbacks → GUI updates
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SignalBridge(QObject):
    session_created = pyqtSignal(dict)       # session.info()
    session_closed  = pyqtSignal(str)        # session_id
    data_received   = pyqtSignal(str, int)   # session_id, byte count
    proxy_request   = pyqtSignal(str, str, int)  # method, host, port
    status_update   = pyqtSignal(str)        # status bar message


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Style Constants
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STYLE_SHEET = """
QMainWindow {
    background-color: #1e1e2e;
}
QTabWidget::pane {
    border: 1px solid #313244;
    background-color: #1e1e2e;
}
QTabBar::tab {
    background-color: #313244;
    color: #cdd6f4;
    padding: 8px 20px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}
QTabBar::tab:selected {
    background-color: #45475a;
    color: #89b4fa;
    font-weight: bold;
}
QGroupBox {
    color: #89b4fa;
    border: 1px solid #45475a;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 16px;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}
QPushButton {
    background-color: #89b4fa;
    color: #1e1e2e;
    border: none;
    padding: 8px 18px;
    border-radius: 6px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #74c7ec;
}
QPushButton:pressed {
    background-color: #585b70;
}
QPushButton:disabled {
    background-color: #45475a;
    color: #6c7086;
}
QPushButton[danger="true"] {
    background-color: #f38ba8;
}
QPushButton[danger="true"]:hover {
    background-color: #eba0ac;
}
QPushButton[success="true"] {
    background-color: #a6e3a1;
}
QLineEdit, QSpinBox, QComboBox {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 5px;
    padding: 6px;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border: 1px solid #89b4fa;
}
QTextEdit, QPlainTextEdit {
    background-color: #11111b;
    color: #a6e3a1;
    border: 1px solid #313244;
    border-radius: 5px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}
QTableWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
    gridline-color: #313244;
    border: 1px solid #45475a;
    border-radius: 5px;
}
QTableWidget::item {
    padding: 4px;
}
QTableWidget::item:selected {
    background-color: #45475a;
}
QHeaderView::section {
    background-color: #313244;
    color: #89b4fa;
    padding: 6px;
    border: 1px solid #45475a;
    font-weight: bold;
}
QLabel {
    color: #cdd6f4;
}
QStatusBar {
    background-color: #181825;
    color: #a6adc8;
}
QCheckBox {
    color: #cdd6f4;
}
QCheckBox::indicator:checked {
    background-color: #89b4fa;
    border-radius: 3px;
}
"""

MONO_FONT = QFont("Consolas", 10)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tab 1 — Dashboard
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DashboardTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self._build_ui()

        # refresh every 2 seconds
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(2000)

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # ── header ───────────────────────────────────────────────
        header = QLabel(f"🔐  {Settings.APP_NAME}  v{Settings.APP_VERSION}")
        header.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("color: #89b4fa; padding: 16px;")
        layout.addWidget(header)

        subtitle = QLabel(
            "End-to-end encrypted traffic protection"
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #6c7086; font-size: 13px;")
        layout.addWidget(subtitle)

        # ── status cards ─────────────────────────────────────────
        cards_layout = QHBoxLayout()

        self.card_tunnel = self._make_card("Tunnel Server", "⏹ Stopped")
        self.card_proxy  = self._make_card("Proxy Server",  "⏹ Stopped")
        self.card_sessions = self._make_card("Active Sessions", "0")
        self.card_keys   = self._make_card("Keys on Disk", "—")

        cards_layout.addWidget(self.card_tunnel)
        cards_layout.addWidget(self.card_proxy)
        cards_layout.addWidget(self.card_sessions)
        cards_layout.addWidget(self.card_keys)
        layout.addLayout(cards_layout)

        # ── info group ───────────────────────────────────────────
        info_group = QGroupBox("System Information")
        info_layout = QFormLayout(info_group)

        self.lbl_tunnel_addr = QLabel("—")
        self.lbl_proxy_addr  = QLabel("—")
        self.lbl_cipher      = QLabel(Settings.DEFAULT_CIPHER)
        self.lbl_uptime      = QLabel("—")

        info_layout.addRow("Tunnel Address:", self.lbl_tunnel_addr)
        info_layout.addRow("Proxy Address:",  self.lbl_proxy_addr)
        info_layout.addRow("Default Cipher:", self.lbl_cipher)
        info_layout.addRow("Uptime:",         self.lbl_uptime)
        layout.addWidget(info_group)

        layout.addStretch()

    def _make_card(self, title: str, value: str) -> QGroupBox:
        card = QGroupBox(title)
        card.setFixedHeight(100)
        vl = QVBoxLayout(card)
        lbl = QLabel(value)
        lbl.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setObjectName("card_value")
        vl.addWidget(lbl)
        return card

    def _card_value(self, card: QGroupBox) -> QLabel:
        return card.findChild(QLabel, "card_value")

    def refresh(self):
        """Called by parent window with live state."""
        pass  # filled in by MainWindow

    def update_status(
        self,
        tunnel_running: bool,
        proxy_running: bool,
        session_count: int,
        key_count: int,
        start_time: float,
    ):
        self._card_value(self.card_tunnel).setText(
            "✅ Running" if tunnel_running else "⏹ Stopped"
        )
        self._card_value(self.card_proxy).setText(
            "✅ Running" if proxy_running else "⏹ Stopped"
        )
        self._card_value(self.card_sessions).setText(str(session_count))
        self._card_value(self.card_keys).setText(str(key_count))

        if tunnel_running:
            self.lbl_tunnel_addr.setText(
                f"{Settings.TUNNEL_HOST}:{Settings.TUNNEL_PORT}"
            )
        else:
            self.lbl_tunnel_addr.setText("—")

        if proxy_running:
            self.lbl_proxy_addr.setText(
                f"{Settings.PROXY_HOST}:{Settings.PROXY_PORT}"
            )
        else:
            self.lbl_proxy_addr.setText("—")

        elapsed = int(time.time() - start_time)
        h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
        self.lbl_uptime.setText(f"{h:02d}:{m:02d}:{s:02d}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tab 2 — Tunnel Server
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TunnelServerTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.tunnel_server: TunnelServer | None = None
        self.session_manager = SessionManager(
            timeout=Settings.SESSION_TIMEOUT
        )
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # ── config ───────────────────────────────────────────────
        config_group = QGroupBox("Server Configuration")
        config_layout = QGridLayout(config_group)

        config_layout.addWidget(QLabel("Bind Host:"), 0, 0)
        self.txt_host = QLineEdit(Settings.TUNNEL_HOST)
        config_layout.addWidget(self.txt_host, 0, 1)

        config_layout.addWidget(QLabel("Bind Port:"), 0, 2)
        self.spn_port = QSpinBox()
        self.spn_port.setRange(1, 65535)
        self.spn_port.setValue(Settings.TUNNEL_PORT)
        config_layout.addWidget(self.spn_port, 0, 3)

        config_layout.addWidget(QLabel("Server ID:"), 1, 0)
        self.txt_server_id = QLineEdit("securecrypt-server")
        config_layout.addWidget(self.txt_server_id, 1, 1)

        config_layout.addWidget(QLabel("Forward Host:"), 1, 2)
        self.txt_fwd_host = QLineEdit("")
        self.txt_fwd_host.setPlaceholderText("Optional (e.g. 127.0.0.1)")
        config_layout.addWidget(self.txt_fwd_host, 1, 3)

        config_layout.addWidget(QLabel("Forward Port:"), 2, 0)
        self.spn_fwd_port = QSpinBox()
        self.spn_fwd_port.setRange(0, 65535)
        self.spn_fwd_port.setValue(0)
        config_layout.addWidget(self.spn_fwd_port, 2, 1)

        layout.addWidget(config_group)

        # ── controls ─────────────────────────────────────────────
        btn_layout = QHBoxLayout()
        self.btn_start = QPushButton("▶  Start Server")
        self.btn_start.clicked.connect(self.start_server)
        btn_layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("⏹  Stop Server")
        self.btn_stop.setProperty("danger", True)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_server)
        btn_layout.addWidget(self.btn_stop)

        self.btn_refresh = QPushButton("🔄  Refresh Sessions")
        self.btn_refresh.clicked.connect(self.refresh_sessions)
        btn_layout.addWidget(self.btn_refresh)

        layout.addLayout(btn_layout)

        # ── session table ────────────────────────────────────────
        sessions_group = QGroupBox("Active Sessions")
        sessions_layout = QVBoxLayout(sessions_group)

        self.tbl_sessions = QTableWidget(0, 7)
        self.tbl_sessions.setHorizontalHeaderLabels([
            "Session ID", "Peer", "Cipher", "Created",
            "Last Activity", "Sent", "Received",
        ])
        self.tbl_sessions.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.tbl_sessions.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        sessions_layout.addWidget(self.tbl_sessions)
        layout.addWidget(sessions_group)

        # connect signals
        self.bridge.session_created.connect(self._on_session_created)
        self.bridge.session_closed.connect(self._on_session_closed)

    def start_server(self):
        try:
            fwd_host = self.txt_fwd_host.text().strip() or None
            fwd_port = self.spn_fwd_port.value() or None

            self.tunnel_server = TunnelServer(
                host=self.txt_host.text().strip(),
                port=self.spn_port.value(),
                forward_host=fwd_host,
                forward_port=fwd_port,
                session_manager=self.session_manager,
                server_id=self.txt_server_id.text().strip(),
                on_session_created=self._cb_session_created,
                on_session_closed=self._cb_session_closed,
                on_data_received=self._cb_data_received,
            )
            self.tunnel_server.start()

            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
            self.txt_host.setEnabled(False)
            self.spn_port.setEnabled(False)
            self.bridge.status_update.emit("Tunnel server started")

        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def stop_server(self):
        if self.tunnel_server:
            self.tunnel_server.stop()
            self.tunnel_server = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.txt_host.setEnabled(True)
        self.spn_port.setEnabled(True)
        self.tbl_sessions.setRowCount(0)
        self.bridge.status_update.emit("Tunnel server stopped")

    def refresh_sessions(self):
        infos = self.session_manager.all_info()
        self.tbl_sessions.setRowCount(len(infos))
        for row, info in enumerate(infos):
            self.tbl_sessions.setItem(
                row, 0, QTableWidgetItem(info["session_id"][:16] + "…")
            )
            self.tbl_sessions.setItem(
                row, 1, QTableWidgetItem(info["peer"])
            )
            self.tbl_sessions.setItem(
                row, 2, QTableWidgetItem(info["cipher"])
            )
            self.tbl_sessions.setItem(
                row, 3, QTableWidgetItem(
                    datetime.fromtimestamp(
                        info["created"]
                    ).strftime("%H:%M:%S")
                )
            )
            self.tbl_sessions.setItem(
                row, 4, QTableWidgetItem(
                    datetime.fromtimestamp(
                        info["last_activity"]
                    ).strftime("%H:%M:%S")
                )
            )
            self.tbl_sessions.setItem(
                row, 5, QTableWidgetItem(
                    self._fmt_bytes(info["bytes_sent"])
                )
            )
            self.tbl_sessions.setItem(
                row, 6, QTableWidgetItem(
                    self._fmt_bytes(info["bytes_received"])
                )
            )

    @staticmethod
    def _fmt_bytes(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    # ── thread-safe callbacks ────────────────────────────────────
    def _cb_session_created(self, session: Session):
        self.bridge.session_created.emit(session.info())

    def _cb_session_closed(self, sid: str):
        self.bridge.session_closed.emit(sid)

    def _cb_data_received(self, sid: str, data: bytes):
        self.bridge.data_received.emit(sid, len(data))

    def _on_session_created(self, info: dict):
        self.refresh_sessions()

    def _on_session_closed(self, sid: str):
        self.refresh_sessions()

    @property
    def is_running(self) -> bool:
        return self.tunnel_server is not None and self.tunnel_server.is_running


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tab 3 — Tunnel Client
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TunnelClientTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.tunnel_client: TunnelClient | None = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # ── connection settings ──────────────────────────────────
        conn_group = QGroupBox("Remote Tunnel Server")
        conn_layout = QGridLayout(conn_group)

        conn_layout.addWidget(QLabel("Remote Host:"), 0, 0)
        self.txt_remote_host = QLineEdit("127.0.0.1")
        conn_layout.addWidget(self.txt_remote_host, 0, 1)

        conn_layout.addWidget(QLabel("Remote Port:"), 0, 2)
        self.spn_remote_port = QSpinBox()
        self.spn_remote_port.setRange(1, 65535)
        self.spn_remote_port.setValue(Settings.TUNNEL_PORT)
        conn_layout.addWidget(self.spn_remote_port, 0, 3)

        conn_layout.addWidget(QLabel("Local Listen Host:"), 1, 0)
        self.txt_local_host = QLineEdit("127.0.0.1")
        self.txt_local_host.setPlaceholderText("Optional")
        conn_layout.addWidget(self.txt_local_host, 1, 1)

        conn_layout.addWidget(QLabel("Local Listen Port:"), 1, 2)
        self.spn_local_port = QSpinBox()
        self.spn_local_port.setRange(0, 65535)
        self.spn_local_port.setValue(0)
        conn_layout.addWidget(self.spn_local_port, 1, 3)

        layout.addWidget(conn_group)

        # ── buttons ──────────────────────────────────────────────
        btn_layout = QHBoxLayout()

        self.btn_connect = QPushButton("🔗  Connect")
        self.btn_connect.clicked.connect(self.connect_tunnel)
        btn_layout.addWidget(self.btn_connect)

        self.btn_disconnect = QPushButton("❌  Disconnect")
        self.btn_disconnect.setProperty("danger", True)
        self.btn_disconnect.setEnabled(False)
        self.btn_disconnect.clicked.connect(self.disconnect_tunnel)
        btn_layout.addWidget(self.btn_disconnect)

        layout.addLayout(btn_layout)

        # ── session info ─────────────────────────────────────────
        info_group = QGroupBox("Session Info")
        info_layout = QFormLayout(info_group)

        self.lbl_status   = QLabel("Disconnected")
        self.lbl_sess_id  = QLabel("—")
        self.lbl_cipher   = QLabel("—")
        self.lbl_sent     = QLabel("0 B")
        self.lbl_recv     = QLabel("0 B")

        info_layout.addRow("Status:",     self.lbl_status)
        info_layout.addRow("Session ID:", self.lbl_sess_id)
        info_layout.addRow("Cipher:",     self.lbl_cipher)
        info_layout.addRow("Sent:",       self.lbl_sent)
        info_layout.addRow("Received:",   self.lbl_recv)
        layout.addWidget(info_group)

        # ── send test data ───────────────────────────────────────
        test_group = QGroupBox("Send Test Data")
        test_layout = QHBoxLayout(test_group)

        self.txt_test_msg = QLineEdit()
        self.txt_test_msg.setPlaceholderText(
            "Type a message to send through the encrypted tunnel…"
        )
        test_layout.addWidget(self.txt_test_msg)

        self.btn_send = QPushButton("📤 Send")
        self.btn_send.setEnabled(False)
        self.btn_send.clicked.connect(self.send_test)
        test_layout.addWidget(self.btn_send)
        layout.addWidget(test_group)

        layout.addStretch()

        # refresh timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_info)
        self._timer.start(1000)

    def connect_tunnel(self):
        def _do_connect():
            try:
                local_host = self.txt_local_host.text().strip() or None
                local_port = self.spn_local_port.value() or None

                self.tunnel_client = TunnelClient(
                    remote_host=self.txt_remote_host.text().strip(),
                    remote_port=self.spn_remote_port.value(),
                    local_listen_host=local_host,
                    local_listen_port=local_port,
                    on_session_created=lambda s: (
                        self.bridge.session_created.emit(s.info())
                    ),
                    on_session_closed=lambda sid: (
                        self.bridge.session_closed.emit(sid)
                    ),
                )
                self.tunnel_client.connect()

                if local_host and local_port:
                    self.tunnel_client.start_local_listener()
                self.tunnel_client.start_keepalive()

                self.bridge.status_update.emit(
                    "Connected to tunnel server"
                )
            except Exception as exc:
                self.bridge.status_update.emit(f"Connect failed: {exc}")

        self.btn_connect.setEnabled(False)
        threading.Thread(target=_do_connect, daemon=True).start()

    def disconnect_tunnel(self):
        if self.tunnel_client:
            self.tunnel_client.disconnect()
            self.tunnel_client = None
        self.btn_connect.setEnabled(True)
        self.btn_disconnect.setEnabled(False)
        self.btn_send.setEnabled(False)
        self.lbl_status.setText("Disconnected")
        self.lbl_sess_id.setText("—")
        self.lbl_cipher.setText("—")
        self.bridge.status_update.emit("Disconnected from tunnel")

    def send_test(self):
        msg = self.txt_test_msg.text().strip()
        if not msg or not self.tunnel_client:
            return
        try:
            self.tunnel_client.send(msg.encode("utf-8"))
            self.txt_test_msg.clear()
            self.bridge.status_update.emit(
                f"Sent {len(msg)} bytes"
            )
        except Exception as exc:
            QMessageBox.warning(self, "Send Error", str(exc))

    def _refresh_info(self):
        if (
            self.tunnel_client
            and self.tunnel_client.is_connected
        ):
            self.btn_connect.setEnabled(False)
            self.btn_disconnect.setEnabled(True)
            self.btn_send.setEnabled(True)
            self.lbl_status.setText("🟢 Connected")
            info = self.tunnel_client.session_info
            if info:
                self.lbl_sess_id.setText(info["session_id"][:16] + "…")
                self.lbl_cipher.setText(info["cipher"])
                self.lbl_sent.setText(
                    TunnelServerTab._fmt_bytes(info["bytes_sent"])
                )
                self.lbl_recv.setText(
                    TunnelServerTab._fmt_bytes(info["bytes_received"])
                )
        else:
            if not self.btn_connect.isEnabled():
                self.btn_connect.setEnabled(True)
                self.btn_disconnect.setEnabled(False)
                self.btn_send.setEnabled(False)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tab 4 — Proxy Server
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ProxyTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.proxy_server: ProxyServer | None = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # ── config ───────────────────────────────────────────────
        config_group = QGroupBox("Proxy Configuration")
        config_layout = QGridLayout(config_group)

        config_layout.addWidget(QLabel("Listen Host:"), 0, 0)
        self.txt_host = QLineEdit(Settings.PROXY_HOST)
        config_layout.addWidget(self.txt_host, 0, 1)

        config_layout.addWidget(QLabel("Listen Port:"), 0, 2)
        self.spn_port = QSpinBox()
        self.spn_port.setRange(1, 65535)
        self.spn_port.setValue(Settings.PROXY_PORT)
        config_layout.addWidget(self.spn_port, 0, 3)

        layout.addWidget(config_group)

        # ── buttons ──────────────────────────────────────────────
        btn_layout = QHBoxLayout()
        self.btn_start = QPushButton("▶  Start Proxy")
        self.btn_start.clicked.connect(self.start_proxy)
        btn_layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("⏹  Stop Proxy")
        self.btn_stop.setProperty("danger", True)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_proxy)
        btn_layout.addWidget(self.btn_stop)

        layout.addLayout(btn_layout)

        # ── info ─────────────────────────────────────────────────
        info_group = QGroupBox("Proxy Info")
        info_fl = QFormLayout(info_group)
        self.lbl_status   = QLabel("⏹ Stopped")
        self.lbl_requests = QLabel("0")
        self.lbl_active   = QLabel("0")
        self.lbl_tunnel   = QLabel("❌ No tunnel")
        info_fl.addRow("Status:",             self.lbl_status)
        info_fl.addRow("Total Requests:",     self.lbl_requests)
        info_fl.addRow("Active Connections:", self.lbl_active)
        info_fl.addRow("Tunnel Encryption:", self.lbl_tunnel)
        layout.addWidget(info_group)

        # ── request log ──────────────────────────────────────────
        log_group = QGroupBox("Recent Requests")
        log_layout = QVBoxLayout(log_group)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setMaximumBlockCount(500)
        log_layout.addWidget(self.txt_log)
        layout.addWidget(log_group)

        # ── browser hint ─────────────────────────────────────────
        hint = QLabel(
            "💡 Set your browser proxy to "
            f"{Settings.PROXY_HOST}:{Settings.PROXY_PORT} "
            "to route traffic through SecureCrypt."
        )
        hint.setStyleSheet("color: #f9e2af; padding: 8px;")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        # signals
        self.bridge.proxy_request.connect(self._on_proxy_request)

        # timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_stats)
        self._timer.start(1000)

    def start_proxy(self):
        try:
            self.proxy_server = ProxyServer(
                host=self.txt_host.text().strip(),
                port=self.spn_port.value(),
                on_request=self._cb_request,
            )
            self.proxy_server.start()
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
            self.txt_host.setEnabled(False)
            self.spn_port.setEnabled(False)
            self.lbl_status.setText("✅ Running")
            self.bridge.status_update.emit("Proxy server started")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def stop_proxy(self):
        if self.proxy_server:
            self.proxy_server.stop()
            self.proxy_server = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.txt_host.setEnabled(True)
        self.spn_port.setEnabled(True)
        self.lbl_status.setText("⏹ Stopped")
        self.bridge.status_update.emit("Proxy server stopped")

    def attach_tunnel_session(self, session: Session | None):
        if self.proxy_server:
            self.proxy_server.tunnel_session = session

    def _cb_request(self, method: str, host: str, port: int):
        self.bridge.proxy_request.emit(method, host, port)

    def _on_proxy_request(self, method: str, host: str, port: int):
        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_log.appendPlainText(
            f"[{ts}]  {method}  {host}:{port}"
        )

    def _refresh_stats(self):
        if self.proxy_server and self.proxy_server.is_running:
            stats = self.proxy_server.stats()
            self.lbl_requests.setText(str(stats["total_requests"]))
            self.lbl_active.setText(str(stats["active_connections"]))
            self.lbl_tunnel.setText(
                "✅ Encrypted" if stats["tunnel_active"]
                else "❌ Direct"
            )

    @property
    def is_running(self) -> bool:
        return (
            self.proxy_server is not None
            and self.proxy_server.is_running
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tab 5 — Crypto Tools
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class CryptoToolsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._aes_key: bytes | None = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # ── AES section ──────────────────────────────────────────
        aes_group = QGroupBox("AES-256-GCM Encrypt / Decrypt")
        aes_layout = QVBoxLayout(aes_group)

        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("AES Key (hex):"))
        self.txt_aes_key = QLineEdit()
        self.txt_aes_key.setPlaceholderText("Click Generate or paste 64 hex chars")
        key_row.addWidget(self.txt_aes_key)
        self.btn_gen_key = QPushButton("🔑 Generate")
        self.btn_gen_key.clicked.connect(self._gen_aes_key)
        key_row.addWidget(self.btn_gen_key)
        aes_layout.addLayout(key_row)

        self.txt_plain = QTextEdit()
        self.txt_plain.setPlaceholderText("Plaintext…")
        self.txt_plain.setMaximumHeight(100)
        aes_layout.addWidget(self.txt_plain)

        enc_dec_row = QHBoxLayout()
        self.btn_encrypt = QPushButton("🔒 Encrypt")
        self.btn_encrypt.clicked.connect(self._encrypt)
        enc_dec_row.addWidget(self.btn_encrypt)
        self.btn_decrypt = QPushButton("🔓 Decrypt")
        self.btn_decrypt.clicked.connect(self._decrypt)
        enc_dec_row.addWidget(self.btn_decrypt)
        aes_layout.addLayout(enc_dec_row)

        self.txt_cipher = QTextEdit()
        self.txt_cipher.setPlaceholderText("Ciphertext (hex)…")
        self.txt_cipher.setMaximumHeight(100)
        aes_layout.addWidget(self.txt_cipher)

        layout.addWidget(aes_group)

        # ── Hash section ─────────────────────────────────────────
        hash_group = QGroupBox("Hashing")
        hash_layout = QVBoxLayout(hash_group)

        hash_input_row = QHBoxLayout()
        self.txt_hash_input = QLineEdit()
        self.txt_hash_input.setPlaceholderText("Data to hash…")
        hash_input_row.addWidget(self.txt_hash_input)

        self.cmb_hash = QComboBox()
        self.cmb_hash.addItems(["SHA-256", "SHA-512", "BLAKE2b"])
        hash_input_row.addWidget(self.cmb_hash)

        self.btn_hash = QPushButton("#️⃣ Hash")
        self.btn_hash.clicked.connect(self._hash)
        hash_input_row.addWidget(self.btn_hash)
        hash_layout.addLayout(hash_input_row)

        self.txt_hash_output = QLineEdit()
        self.txt_hash_output.setReadOnly(True)
        self.txt_hash_output.setPlaceholderText("Hash output…")
        hash_layout.addWidget(self.txt_hash_output)

        layout.addWidget(hash_group)

        # ── RSA section ──────────────────────────────────────────
        rsa_group = QGroupBox("RSA Quick Test")
        rsa_layout = QVBoxLayout(rsa_group)

        self.btn_rsa_test = QPushButton(
            "🧪  Generate RSA-4096 → Encrypt → Decrypt round-trip"
        )
        self.btn_rsa_test.clicked.connect(self._rsa_test)
        rsa_layout.addWidget(self.btn_rsa_test)

        self.txt_rsa_result = QPlainTextEdit()
        self.txt_rsa_result.setReadOnly(True)
        self.txt_rsa_result.setMaximumHeight(120)
        rsa_layout.addWidget(self.txt_rsa_result)

        layout.addWidget(rsa_group)

        # ── ECC section ──────────────────────────────────────────
        ecc_group = QGroupBox("ECC Quick Test")
        ecc_layout = QVBoxLayout(ecc_group)

        self.btn_ecc_test = QPushButton(
            "🧪  ECDH Key Exchange + Sign/Verify round-trip"
        )
        self.btn_ecc_test.clicked.connect(self._ecc_test)
        ecc_layout.addWidget(self.btn_ecc_test)

        self.txt_ecc_result = QPlainTextEdit()
        self.txt_ecc_result.setReadOnly(True)
        self.txt_ecc_result.setMaximumHeight(120)
        ecc_layout.addWidget(self.txt_ecc_result)

        layout.addWidget(ecc_group)
        layout.addStretch()

    def _gen_aes_key(self):
        self._aes_key = SecureRandom.generate_bytes(32)
        self.txt_aes_key.setText(self._aes_key.hex())

    def _get_aes(self) -> AESCrypto | None:
        hex_key = self.txt_aes_key.text().strip()
        if not hex_key:
            QMessageBox.warning(
                self, "No Key", "Generate or enter an AES key first."
            )
            return None
        try:
            key = bytes.fromhex(hex_key)
        except ValueError:
            QMessageBox.warning(self, "Bad Key", "Invalid hex key.")
            return None
        if len(key) not in (16, 24, 32):
            QMessageBox.warning(
                self, "Bad Key", "Key must be 16, 24 or 32 bytes."
            )
            return None
        return AESCrypto(key=key)

    def _encrypt(self):
        aes = self._get_aes()
        if not aes:
            return
        pt = self.txt_plain.toPlainText().encode("utf-8")
        if not pt:
            return
        nonce, ct = aes.encrypt_gcm(pt)
        # store as nonce_hex:ct_hex
        self.txt_cipher.setPlainText(
            f"{nonce.hex()}:{ct.hex()}"
        )

    def _decrypt(self):
        aes = self._get_aes()
        if not aes:
            return
        raw = self.txt_cipher.toPlainText().strip()
        if ":" not in raw:
            QMessageBox.warning(
                self, "Format", "Expected nonce_hex:ciphertext_hex"
            )
            return
        try:
            nonce_hex, ct_hex = raw.split(":", 1)
            nonce = bytes.fromhex(nonce_hex)
            ct    = bytes.fromhex(ct_hex)
            pt    = aes.decrypt_gcm(nonce, ct)
            self.txt_plain.setPlainText(pt.decode("utf-8"))
        except Exception as exc:
            QMessageBox.warning(self, "Decrypt Error", str(exc))

    def _hash(self):
        data = self.txt_hash_input.text().encode("utf-8")
        if not data:
            return
        algo = self.cmb_hash.currentText()
        if algo == "SHA-256":
            result = HashCrypto.sha256(data)
        elif algo == "SHA-512":
            result = HashCrypto.sha512(data)
        else:
            result = HashCrypto.blake2b(data)
        self.txt_hash_output.setText(result.hex())

    def _rsa_test(self):
        self.txt_rsa_result.clear()
        try:
            t0 = time.time()
            rsa = RSACrypto(key_size=4096)
            rsa.generate_keys()
            t1 = time.time()

            msg = b"Hello from SecureCrypt RSA test!"
            ct  = rsa.encrypt(msg)
            pt  = rsa.decrypt(ct)

            sig    = rsa.sign(msg)
            valid  = rsa.verify(msg, sig)

            self.txt_rsa_result.appendPlainText(
                f"Key generation: {t1 - t0:.2f}s"
            )
            self.txt_rsa_result.appendPlainText(
                f"Plaintext:  {msg.decode()}"
            )
            self.txt_rsa_result.appendPlainText(
                f"Decrypted:  {pt.decode()}"
            )
            self.txt_rsa_result.appendPlainText(
                f"Match: {'✅' if pt == msg else '❌'}"
            )
            self.txt_rsa_result.appendPlainText(
                f"Signature valid: {'✅' if valid else '❌'}"
            )
        except Exception as exc:
            self.txt_rsa_result.appendPlainText(f"Error: {exc}")

    def _ecc_test(self):
        self.txt_ecc_result.clear()
        try:
            alice = ECCCrypto("SECP384R1")
            alice.generate_keys()
            bob = ECCCrypto("SECP384R1")
            bob.generate_keys()

            key_a = alice.derive_shared_key(bob.public_key)
            key_b = bob.derive_shared_key(alice.public_key)

            msg = b"ECDH shared-secret test"
            sig = alice.sign(msg)
            valid = alice.verify(msg, sig)

            self.txt_ecc_result.appendPlainText(
                f"Alice shared key: {key_a.hex()[:32]}…"
            )
            self.txt_ecc_result.appendPlainText(
                f"Bob   shared key: {key_b.hex()[:32]}…"
            )
            self.txt_ecc_result.appendPlainText(
                f"Keys match: {'✅' if key_a == key_b else '❌'}"
            )
            self.txt_ecc_result.appendPlainText(
                f"ECDSA signature valid: {'✅' if valid else '❌'}"
            )
        except Exception as exc:
            self.txt_ecc_result.appendPlainText(f"Error: {exc}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tab 6 — Key Manager
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class KeyManagerTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.km = KeyManager()
        self._build_ui()
        self._refresh_list()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # ── generate ─────────────────────────────────────────────
        gen_group = QGroupBox("Generate Key Pair")
        gen_layout = QGridLayout(gen_group)

        gen_layout.addWidget(QLabel("Name:"), 0, 0)
        self.txt_name = QLineEdit("server")
        gen_layout.addWidget(self.txt_name, 0, 1)

        gen_layout.addWidget(QLabel("Type:"), 0, 2)
        self.cmb_type = QComboBox()
        self.cmb_type.addItems(["RSA-4096", "ECC-P384"])
        gen_layout.addWidget(self.cmb_type, 0, 3)

        gen_layout.addWidget(QLabel("Password:"), 1, 0)
        self.txt_pass = QLineEdit()
        self.txt_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_pass.setPlaceholderText("Optional encryption password")
        gen_layout.addWidget(self.txt_pass, 1, 1, 1, 2)

        self.btn_generate = QPushButton("🔑  Generate")
        self.btn_generate.clicked.connect(self._generate)
        gen_layout.addWidget(self.btn_generate, 1, 3)

        layout.addWidget(gen_group)

        # ── key list ─────────────────────────────────────────────
        list_group = QGroupBox("Keys on Disk")
        list_layout = QVBoxLayout(list_group)

        self.tbl_keys = QTableWidget(0, 2)
        self.tbl_keys.setHorizontalHeaderLabels(["File Name", "Path"])
        self.tbl_keys.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.tbl_keys.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        list_layout.addWidget(self.tbl_keys)

        btn_row = QHBoxLayout()
        self.btn_refresh_keys = QPushButton("🔄  Refresh")
        self.btn_refresh_keys.clicked.connect(self._refresh_list)
        btn_row.addWidget(self.btn_refresh_keys)

        self.btn_delete_key = QPushButton("🗑️  Delete Selected")
        self.btn_delete_key.setProperty("danger", True)
        self.btn_delete_key.clicked.connect(self._delete_selected)
        btn_row.addWidget(self.btn_delete_key)

        list_layout.addLayout(btn_row)
        layout.addWidget(list_group)
        layout.addStretch()

    def _generate(self):
        name = self.txt_name.text().strip()
        if not name:
            QMessageBox.warning(self, "Error", "Enter a key name.")
            return
        pwd = self.txt_pass.text().encode() if self.txt_pass.text() else None
        ktype = self.cmb_type.currentText()

        try:
            if ktype.startswith("RSA"):
                priv, pub = self.km.generate_rsa_keypair(
                    name, key_size=4096, password=pwd
                )
            else:
                priv, pub = self.km.generate_ecc_keypair(
                    name, curve="SECP384R1", password=pwd
                )
            QMessageBox.information(
                self, "Success",
                f"Keys generated:\n  {priv}\n  {pub}",
            )
            self._refresh_list()
            self.bridge.status_update.emit(
                f"{ktype} key pair '{name}' generated"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _refresh_list(self):
        keys = self.km.list_keys()
        self.tbl_keys.setRowCount(len(keys))
        for row, fname in enumerate(keys):
            self.tbl_keys.setItem(row, 0, QTableWidgetItem(fname))
            self.tbl_keys.setItem(
                row, 1,
                QTableWidgetItem(
                    os.path.join(self.km.keys_dir, fname)
                ),
            )

    def _delete_selected(self):
        row = self.tbl_keys.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Error", "Select a key to delete.")
            return
        fname = self.tbl_keys.item(row, 0).text()
        reply = QMessageBox.question(
            self, "Confirm",
            f"Delete {fname}? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            path = os.path.join(self.km.keys_dir, fname)
            try:
                os.remove(path)
                self._refresh_list()
                self.bridge.status_update.emit(f"Deleted {fname}")
            except Exception as exc:
                QMessageBox.critical(self, "Error", str(exc))

    @property
    def key_count(self) -> int:
        return self.tbl_keys.rowCount()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tab 7 — Logs
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class LogsTab(QWidget):
    def __init__(self, log_handler: QtLogHandler, parent=None):
        super().__init__(parent)
        self.log_handler = log_handler
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        toolbar = QHBoxLayout()
        self.chk_auto = QCheckBox("Auto-scroll")
        self.chk_auto.setChecked(True)
        toolbar.addWidget(self.chk_auto)

        self.btn_clear = QPushButton("🗑️  Clear")
        self.btn_clear.clicked.connect(self._clear)
        toolbar.addWidget(self.btn_clear)

        self.btn_save = QPushButton("💾  Save to File")
        self.btn_save.clicked.connect(self._save)
        toolbar.addWidget(self.btn_save)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setMaximumBlockCount(5000)
        self.txt_log.setFont(MONO_FONT)
        layout.addWidget(self.txt_log)

        # connect log handler
        self.log_handler.signal_emitter.log_message.connect(
            self._append_log
        )

    def _append_log(self, msg: str):
        self.txt_log.appendPlainText(msg)
        if self.chk_auto.isChecked():
            cursor = self.txt_log.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.txt_log.setTextCursor(cursor)

    def _clear(self):
        self.txt_log.clear()

    def _save(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Log", "securecrypt.log", "Log Files (*.log *.txt)"
        )
        if path:
            with open(path, "w") as f:
                f.write(self.txt_log.toPlainText())


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Main Window
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.start_time = time.time()
        self.bridge = SignalBridge()
        self.log_handler = QtLogHandler()

        # set up Python logging
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        root_logger.addHandler(self.log_handler)

        # also log to console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)-8s] %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        ))
        root_logger.addHandler(console_handler)

        self.logger = logging.getLogger("SecureCrypt.Main")

        self._init_window()
        self._init_tabs()
        self._init_status_bar()
        self._init_timers()

        self.logger.info(
            "%s v%s started", Settings.APP_NAME, Settings.APP_VERSION
        )

    def _init_window(self):
        self.setWindowTitle(
            f"{Settings.APP_NAME} — Encrypted Traffic Protection"
        )
        self.setMinimumSize(1000, 700)
        self.resize(1200, 800)

    def _init_tabs(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.tab_dashboard     = DashboardTab(self.bridge)
        self.tab_tunnel_server = TunnelServerTab(self.bridge)
        self.tab_tunnel_client = TunnelClientTab(self.bridge)
        self.tab_proxy         = ProxyTab(self.bridge)
        self.tab_crypto        = CryptoToolsTab()
        self.tab_keys          = KeyManagerTab(self.bridge)
        self.tab_logs          = LogsTab(self.log_handler)

        self.tabs.addTab(self.tab_dashboard,     "📊 Dashboard")
        self.tabs.addTab(self.tab_tunnel_server, "🖥️ Tunnel Server")
        self.tabs.addTab(self.tab_tunnel_client, "🔗 Tunnel Client")
        self.tabs.addTab(self.tab_proxy,         "🌐 Proxy")
        self.tabs.addTab(self.tab_crypto,        "🔐 Crypto Tools")
        self.tabs.addTab(self.tab_keys,          "🔑 Key Manager")
        self.tabs.addTab(self.tab_logs,          "📝 Logs")

    def _init_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready")
        self.status_bar.addPermanentWidget(self.status_label)

        self.bridge.status_update.connect(self._update_status)

    def _update_status(self, msg: str):
        self.status_label.setText(msg)
        self.logger.info("Status: %s", msg)

    def _init_timers(self):
        self.dashboard_timer = QTimer(self)
        self.dashboard_timer.timeout.connect(self._refresh_dashboard)
        self.dashboard_timer.start(2000)

    def _refresh_dashboard(self):
        self.tab_dashboard.update_status(
            tunnel_running=self.tab_tunnel_server.is_running,
            proxy_running=self.tab_proxy.is_running,
            session_count=self.tab_tunnel_server.session_manager.active_count(),
            key_count=self.tab_keys.key_count,
            start_time=self.start_time,
        )

    # ── clean shutdown ───────────────────────────────────────────
    def closeEvent(self, event):
        self.logger.info("Shutting down…")

        if self.tab_tunnel_server.is_running:
            self.tab_tunnel_server.stop_server()

        if self.tab_tunnel_client.tunnel_client:
            self.tab_tunnel_client.disconnect_tunnel()

        if self.tab_proxy.is_running:
            self.tab_proxy.stop_proxy()

        self.logger.info("Goodbye!")
        event.accept()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Entry Point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    # Ensure keys directory exists
    os.makedirs(Settings.KEYS_DIR, exist_ok=True)

    app = QApplication(sys.argv)
    app.setApplicationName(Settings.APP_NAME)
    app.setApplicationVersion(Settings.APP_VERSION)
    app.setStyleSheet(STYLE_SHEET)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()