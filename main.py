"""
SecureCrypt — Main Entry Point & PyQt6 GUI

Tabs
────
1. Dashboard       – status overview, quick actions
2. Tunnel Server   – start/stop server, view sessions
3. Tunnel Client   – connect to remote server
4. Proxy Server    – start/stop HTTP/S proxy
5. Relay Server    – start/stop relay for peer-to-peer
6. Crypto Tools    – encrypt/decrypt/hash playground
7. Key Manager     – generate, list, delete keys
8. Logs            – live scrolling log output

Every network service runs in background threads; the GUI stays
responsive via Qt signals.
"""

import sys
import os
import time
import logging
import threading
import socket as _socket
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QSpinBox, QFileDialog, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QStatusBar, QCheckBox, QPlainTextEdit,
    QSizePolicy, QListWidget, QListWidgetItem,
    QAbstractItemView,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor, QIcon, QTextCursor

from config.settings import Settings

from core.crypto_engine import (
    AESCrypto, RSACrypto, ECCCrypto, HashCrypto,
    CipherFactory,
)

from utils.random_gen     import SecureRandom
from utils.key_manager    import KeyManager
from utils.secure_storage import SecureStorage
from utils.framing        import Framing, MessageType

from traffic.handshake       import HandshakeProtocol
from traffic.session_manager import Session, SessionManager
from traffic.tunnel_server   import TunnelServer, TunnelClient
from traffic.proxy_client    import ProxyServer, SystemProxyConfig
from traffic.relay_server import RelayServer
from traffic.peer_client  import PeerClient
from core.e2e_engine      import E2EEngine
from core.file_transfer   import FileMetadata



def _get_local_ip() -> str:
    """Return the LAN IP other machines can reach this one on."""
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))          # doesn't actually send data
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
    
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

    def _build_ui(self):
        layout = QVBoxLayout(self)

        header = QLabel(f"🔐  {Settings.APP_NAME}  v{Settings.APP_VERSION}")
        header.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("color: #89b4fa; padding: 16px;")
        layout.addWidget(header)

        subtitle = QLabel(
            "End-to-end encrypted traffic protection — multi-cipher"
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #6c7086; font-size: 13px;")
        layout.addWidget(subtitle)

        # ── Status cards ─────────────────────────────────────────
        cards_layout = QHBoxLayout()

        self.card_tunnel   = self._make_card("Tunnel Server",   "⏹ Stopped")
        self.card_proxy    = self._make_card("Proxy Server",    "⏹ Stopped")
        self.card_sessions = self._make_card("Active Sessions", "0")
        self.card_cipher   = self._make_card("Active Cipher",   "—")
        self.card_keys     = self._make_card("Keys on Disk",    "—")

        cards_layout.addWidget(self.card_tunnel)
        cards_layout.addWidget(self.card_proxy)
        cards_layout.addWidget(self.card_sessions)
        cards_layout.addWidget(self.card_cipher)
        cards_layout.addWidget(self.card_keys)
        layout.addLayout(cards_layout)

        # ── Info group ───────────────────────────────────────────
        info_group = QGroupBox("System Information")
        info_layout = QFormLayout(info_group)

        self.lbl_tunnel_addr  = QLabel("—")
        self.lbl_proxy_addr   = QLabel("—")
        self.lbl_tunnel_cipher = QLabel("—")
        self.lbl_proxy_cipher = QLabel("—")
        self.lbl_cipher_type  = QLabel("—")
        self.lbl_uptime       = QLabel("—")

        info_layout.addRow("Tunnel Address:",  self.lbl_tunnel_addr)
        info_layout.addRow("Proxy Address:",   self.lbl_proxy_addr)
        info_layout.addRow("Tunnel Cipher:",   self.lbl_tunnel_cipher)
        info_layout.addRow("Proxy Encryption:", self.lbl_proxy_cipher)
        info_layout.addRow("Auth Method:",     self.lbl_cipher_type)
        info_layout.addRow("Uptime:",          self.lbl_uptime)
        layout.addWidget(info_group)

        # ── Available ciphers summary ────────────────────────────
        cipher_group = QGroupBox(
            f"📊  Available Ciphers ({len(CipherFactory.list_ciphers())})"
        )
        cipher_layout = QVBoxLayout(cipher_group)

        cipher_text = ""
        for info in CipherFactory.get_all_info():
            aead = "🛡️ AEAD" if info["aead"] else "🔗 HMAC"
            cipher_text += (
                f"  {info['name']:<25s} "
                f"{info['key_bits']:>3d}-bit  "
                f"{aead}  "
                f"{info['speed']}\n"
            )

        lbl_ciphers = QLabel(cipher_text.strip())
        lbl_ciphers.setFont(QFont("Consolas", 10))
        lbl_ciphers.setStyleSheet("color: #a6e3a1;")
        cipher_layout.addWidget(lbl_ciphers)
        layout.addWidget(cipher_group)

        layout.addStretch()

    def _make_card(self, title: str, value: str) -> QGroupBox:
        card = QGroupBox(title)
        card.setFixedHeight(100)
        vl = QVBoxLayout(card)
        lbl = QLabel(value)
        lbl.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setObjectName("card_value")
        vl.addWidget(lbl)
        return card

    def _card_value(self, card: QGroupBox) -> QLabel:
        return card.findChild(QLabel, "card_value")

    def update_status(
        self,
        tunnel_running: bool,
        proxy_running: bool,
        session_count: int,
        key_count: int,
        start_time: float,
        active_cipher: str = "—",
        cipher_details: dict | None = None,
    ):
        self._card_value(self.card_tunnel).setText(
            "✅ Running" if tunnel_running else "⏹ Stopped"
        )
        self._card_value(self.card_proxy).setText(
            "✅ Running" if proxy_running else "⏹ Stopped"
        )
        self._card_value(self.card_sessions).setText(str(session_count))
        self._card_value(self.card_cipher).setText(active_cipher)
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

        self.lbl_tunnel_cipher.setText(active_cipher)

        if cipher_details:
            auth = cipher_details.get("auth_method", "—")
            self.lbl_cipher_type.setText(auth)
            self.lbl_proxy_cipher.setText(
                f"🔒 {active_cipher} ({auth})"
            )
        else:
            self.lbl_proxy_cipher.setText("🔓 No tunnel")
            self.lbl_cipher_type.setText("—")

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

        # ── Network config ───────────────────────────────────────
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
        self.txt_fwd_host.setPlaceholderText("Optional")
        config_layout.addWidget(self.txt_fwd_host, 1, 3)

        config_layout.addWidget(QLabel("Forward Port:"), 2, 0)
        self.spn_fwd_port = QSpinBox()
        self.spn_fwd_port.setRange(0, 65535)
        config_layout.addWidget(self.spn_fwd_port, 2, 1)

        layout.addWidget(config_group)

        # ── Cipher selection ─────────────────────────────────────
        self.cipher_selector = CipherSelectorWidget(
            "🔐 Allowed Ciphers (server preference order)"
        )
        layout.addWidget(self.cipher_selector)

        # ── Controls ─────────────────────────────────────────────
        btn_layout = QHBoxLayout()

        self.btn_start = QPushButton("▶  Start Server")
        self.btn_start.clicked.connect(self.start_server)
        btn_layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("⏹  Stop Server")
        self.btn_stop.setProperty("danger", True)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_server)
        btn_layout.addWidget(self.btn_stop)

        self.btn_refresh = QPushButton("🔄  Refresh")
        self.btn_refresh.clicked.connect(self.refresh_sessions)
        btn_layout.addWidget(self.btn_refresh)

        self.btn_update_ciphers = QPushButton("🔁  Update Ciphers Live")
        self.btn_update_ciphers.setEnabled(False)
        self.btn_update_ciphers.clicked.connect(
            self._update_ciphers_live
        )
        btn_layout.addWidget(self.btn_update_ciphers)

        layout.addLayout(btn_layout)

        # ── Session table ────────────────────────────────────────
        sessions_group = QGroupBox("Active Sessions")
        sessions_layout = QVBoxLayout(sessions_group)

        self.tbl_sessions = QTableWidget(0, 8)
        self.tbl_sessions.setHorizontalHeaderLabels([
            "Session ID", "Peer", "Cipher", "AEAD",
            "Created", "Last Activity", "Sent", "Received",
        ])
        self.tbl_sessions.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.tbl_sessions.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        sessions_layout.addWidget(self.tbl_sessions)
        layout.addWidget(sessions_group)

        self.bridge.session_created.connect(self._on_session_created)
        self.bridge.session_closed.connect(self._on_session_closed)

    def start_server(self):
        try:
            fwd_host = self.txt_fwd_host.text().strip() or None
            fwd_port = self.spn_fwd_port.value() or None

            allowed = self.cipher_selector.get_allowed_ciphers()

            self.tunnel_server = TunnelServer(
                host=self.txt_host.text().strip(),
                port=self.spn_port.value(),
                forward_host=fwd_host,
                forward_port=fwd_port,
                session_manager=self.session_manager,
                server_id=self.txt_server_id.text().strip(),
                allowed_ciphers=allowed,
                on_session_created=self._cb_session_created,
                on_session_closed=self._cb_session_closed,
                on_data_received=self._cb_data_received,
            )
            self.tunnel_server.start()

            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
            self.btn_update_ciphers.setEnabled(True)
            self.txt_host.setEnabled(False)
            self.spn_port.setEnabled(False)

            self.bridge.status_update.emit(
                f"Tunnel started — ciphers: {', '.join(allowed[:3])}…"
            )

        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def stop_server(self):
        if self.tunnel_server:
            self.tunnel_server.stop()
            self.tunnel_server = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_update_ciphers.setEnabled(False)
        self.txt_host.setEnabled(True)
        self.spn_port.setEnabled(True)
        self.tbl_sessions.setRowCount(0)
        self.bridge.status_update.emit("Tunnel server stopped")

    def _update_ciphers_live(self):
        """Hot-update ciphers without restarting the server."""
        if not self.tunnel_server:
            return
        try:
            new_ciphers = self.cipher_selector.get_allowed_ciphers()
            self.tunnel_server.update_allowed_ciphers(new_ciphers)
            self.bridge.status_update.emit(
                f"Ciphers updated: {', '.join(new_ciphers[:3])}…"
            )
        except Exception as exc:
            QMessageBox.warning(self, "Error", str(exc))

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
            details = info.get("cipher_details", {})
            aead_str = "🛡️ Yes" if details.get("aead") else "🔗 HMAC"
            self.tbl_sessions.setItem(
                row, 3, QTableWidgetItem(aead_str)
            )
            self.tbl_sessions.setItem(
                row, 4, QTableWidgetItem(
                    datetime.fromtimestamp(
                        info["created"]
                    ).strftime("%H:%M:%S")
                )
            )
            self.tbl_sessions.setItem(
                row, 5, QTableWidgetItem(
                    datetime.fromtimestamp(
                        info["last_activity"]
                    ).strftime("%H:%M:%S")
                )
            )
            self.tbl_sessions.setItem(
                row, 6, QTableWidgetItem(
                    self._fmt_bytes(info["bytes_sent"])
                )
            )
            self.tbl_sessions.setItem(
                row, 7, QTableWidgetItem(
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
        return (
            self.tunnel_server is not None
            and self.tunnel_server.is_running
        )


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

        # ── Connection settings ──────────────────────────────────
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

        # ── Cipher selection ─────────────────────────────────────
        self.cipher_selector = CipherSelectorWidget(
            "🔐 Preferred Ciphers (client sends this to server)"
        )
        layout.addWidget(self.cipher_selector)

        # ── Buttons ──────────────────────────────────────────────
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

        # ── Session info ─────────────────────────────────────────
        info_group = QGroupBox("Session Info")
        info_layout = QFormLayout(info_group)

        self.lbl_status        = QLabel("Disconnected")
        self.lbl_sess_id       = QLabel("—")
        self.lbl_cipher        = QLabel("—")
        self.lbl_cipher_detail = QLabel("—")
        self.lbl_sent          = QLabel("0 B")
        self.lbl_recv          = QLabel("0 B")

        info_layout.addRow("Status:",          self.lbl_status)
        info_layout.addRow("Session ID:",      self.lbl_sess_id)
        info_layout.addRow("Negotiated Cipher:", self.lbl_cipher)
        info_layout.addRow("Cipher Details:",  self.lbl_cipher_detail)
        info_layout.addRow("Sent:",            self.lbl_sent)
        info_layout.addRow("Received:",        self.lbl_recv)
        layout.addWidget(info_group)

        # ── Test data sender ─────────────────────────────────────
        test_group = QGroupBox("Send Test Data")
        test_layout = QHBoxLayout(test_group)

        self.txt_test_msg = QLineEdit()
        self.txt_test_msg.setPlaceholderText(
            "Type a message to send encrypted…"
        )
        test_layout.addWidget(self.txt_test_msg)

        self.btn_send = QPushButton("📤 Send")
        self.btn_send.setEnabled(False)
        self.btn_send.clicked.connect(self.send_test)
        test_layout.addWidget(self.btn_send)
        layout.addWidget(test_group)

        layout.addStretch()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_info)
        self._timer.start(1000)

    def connect_tunnel(self):
        def _do_connect():
            try:
                local_host = self.txt_local_host.text().strip() or None
                local_port = self.spn_local_port.value() or None

                preferred = self.cipher_selector.get_ordered_preference()

                self.tunnel_client = TunnelClient(
                    remote_host=self.txt_remote_host.text().strip(),
                    remote_port=self.spn_remote_port.value(),
                    local_listen_host=local_host,
                    local_listen_port=local_port,
                    preferred_ciphers=preferred,
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

                negotiated = self.tunnel_client.negotiated_cipher
                self.bridge.status_update.emit(
                    f"Connected — cipher: {negotiated}"
                )
            except Exception as exc:
                self.bridge.status_update.emit(
                    f"Connect failed: {exc}"
                )

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
        self.lbl_cipher_detail.setText("—")
        self.bridge.status_update.emit("Disconnected")

    def send_test(self):
        msg = self.txt_test_msg.text().strip()
        if not msg or not self.tunnel_client:
            return
        try:
            self.tunnel_client.send(msg.encode("utf-8"))
            self.txt_test_msg.clear()
            cipher = self.tunnel_client.negotiated_cipher or "?"
            self.bridge.status_update.emit(
                f"Sent {len(msg)} bytes via {cipher}"
            )
        except Exception as exc:
            QMessageBox.warning(self, "Send Error", str(exc))

    def _refresh_info(self):
        if self.tunnel_client and self.tunnel_client.is_connected:
            self.btn_connect.setEnabled(False)
            self.btn_disconnect.setEnabled(True)
            self.btn_send.setEnabled(True)
            self.lbl_status.setText("🟢 Connected")

            info = self.tunnel_client.session_info
            if info:
                self.lbl_sess_id.setText(
                    info["session_id"][:16] + "…"
                )
                self.lbl_cipher.setText(
                    f"🔒 {info['cipher']}"
                )
                details = info.get("cipher_details", {})
                self.lbl_cipher_detail.setText(
                    f"{details.get('key_bits', '?')}-bit  •  "
                    f"{details.get('auth_method', '?')}  •  "
                    f"AEAD: {'Yes' if details.get('aead') else 'No'}"
                )
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

    @property
    def active_cipher(self) -> str | None:
        """Used by dashboard and proxy tab."""
        if self.tunnel_client and self.tunnel_client.is_connected:
            return self.tunnel_client.negotiated_cipher
        return None

    @property
    def active_session(self) -> Session | None:
        """Used by proxy tab to attach tunnel."""
        if self.tunnel_client and self.tunnel_client.is_connected:
            return self.tunnel_client._session
        return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tab 4 — Proxy Server
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ProxyTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.proxy_server: ProxyServer | None = None
        self.logger = logging.getLogger("SecureCrypt.ProxyTab")
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # ── Config ───────────────────────────────────────────────
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

        # ── Buttons ──────────────────────────────────────────────
        btn_layout = QHBoxLayout()

        self.btn_start = QPushButton("▶  Start Proxy")
        self.btn_start.clicked.connect(self.start_proxy)
        btn_layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("⏹  Stop Proxy")
        self.btn_stop.setProperty("danger", True)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_proxy)
        btn_layout.addWidget(self.btn_stop)

        self.btn_attach = QPushButton("🔗  Attach Tunnel")
        self.btn_attach.setToolTip(
            "Connect proxy to active tunnel session"
        )
        self.btn_attach.clicked.connect(self._attach_tunnel)
        btn_layout.addWidget(self.btn_attach)

        self.btn_detach = QPushButton("🔓  Detach (Direct)")
        self.btn_detach.clicked.connect(self._detach_tunnel)
        btn_layout.addWidget(self.btn_detach)

        self.btn_sys_proxy = QPushButton("🖥️  Set System Proxy")
        self.btn_sys_proxy.clicked.connect(self._set_system_proxy)
        btn_layout.addWidget(self.btn_sys_proxy)

        self.btn_unset_proxy = QPushButton("↩️  Unset")
        self.btn_unset_proxy.setProperty("danger", True)
        self.btn_unset_proxy.clicked.connect(self._unset_system_proxy)
        btn_layout.addWidget(self.btn_unset_proxy)

        layout.addLayout(btn_layout)

        # ── Encryption status ────────────────────────────────────
        enc_group = QGroupBox("🔐 Encryption Status")
        enc_layout = QFormLayout(enc_group)

        self.lbl_status       = QLabel("⏹ Stopped")
        self.lbl_mode         = QLabel("—")
        self.lbl_cipher       = QLabel("🔓 No encryption (direct)")
        self.lbl_cipher_bits  = QLabel("—")
        self.lbl_cipher_aead  = QLabel("—")
        self.lbl_requests     = QLabel("0")
        self.lbl_active       = QLabel("0")
        self.lbl_blocked      = QLabel("0")
        self.lbl_pac          = QLabel("—")

        enc_layout.addRow("Proxy Status:",     self.lbl_status)
        enc_layout.addRow("Mode:",             self.lbl_mode)
        enc_layout.addRow("Tunnel Cipher:",    self.lbl_cipher)
        enc_layout.addRow("Key Strength:",     self.lbl_cipher_bits)
        enc_layout.addRow("Authentication:",   self.lbl_cipher_aead)
        enc_layout.addRow("Total Requests:",   self.lbl_requests)
        enc_layout.addRow("Active Connections:", self.lbl_active)
        enc_layout.addRow("Blocked:",          self.lbl_blocked)
        enc_layout.addRow("PAC File:",         self.lbl_pac)

        layout.addWidget(enc_group)

        # ── Domain blocking ──────────────────────────────────────
        block_group = QGroupBox("🚫 Domain Blocking")
        block_layout = QHBoxLayout(block_group)

        self.txt_block = QLineEdit()
        self.txt_block.setPlaceholderText("e.g. ads.example.com")
        block_layout.addWidget(self.txt_block)

        self.btn_block = QPushButton("🚫 Block")
        self.btn_block.clicked.connect(self._block_domain)
        block_layout.addWidget(self.btn_block)

        self.btn_unblock = QPushButton("✅ Unblock")
        self.btn_unblock.clicked.connect(self._unblock_domain)
        block_layout.addWidget(self.btn_unblock)

        layout.addWidget(block_group)

        # ── Request log ──────────────────────────────────────────
        log_group = QGroupBox("📋 Live Request Log")
        log_layout = QVBoxLayout(log_group)

        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setMaximumBlockCount(500)
        log_layout.addWidget(self.txt_log)
        layout.addWidget(log_group)

        # ── Browser instructions ─────────────────────────────────
        hint_group = QGroupBox("📋 Browser Setup")
        hint_layout = QVBoxLayout(hint_group)

        self.txt_instructions = QPlainTextEdit()
        self.txt_instructions.setReadOnly(True)
        self.txt_instructions.setMaximumHeight(120)
        self.txt_instructions.setPlainText(
            SystemProxyConfig.get_manual_instructions(
                Settings.PROXY_HOST, Settings.PROXY_PORT
            )
        )
        hint_layout.addWidget(self.txt_instructions)
        layout.addWidget(hint_group)

        self.bridge.proxy_request.connect(self._on_proxy_request)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_stats)
        self._timer.start(1000)

    # ── Actions ──────────────────────────────────────────────────

    def start_proxy(self):
        try:
            host = self.txt_host.text().strip()
            port = self.spn_port.value()

            self.proxy_server = ProxyServer(
                host=host,
                port=port,
                on_request=self._cb_request,
            )
            self.proxy_server.start()

            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
            self.txt_host.setEnabled(False)
            self.spn_port.setEnabled(False)
            self.lbl_status.setText("✅ Running")
            self.lbl_pac.setText(f"http://{host}:{port}/proxy.pac")

            self.bridge.status_update.emit(
                f"Proxy started on {host}:{port}"
            )
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
        self.lbl_pac.setText("—")
        self.lbl_cipher.setText("🔓 No encryption")
        self.bridge.status_update.emit("Proxy stopped")

    def _attach_tunnel(self):
        """Attach tunnel session from TunnelClientTab."""
        main_win = self.window()
        if hasattr(main_win, "tab_tunnel_client"):
            session = main_win.tab_tunnel_client.active_session
            cipher  = main_win.tab_tunnel_client.active_cipher
            if session and session.active:
                self.attach_tunnel_session(session)
                self.bridge.status_update.emit(
                    f"Proxy attached to tunnel — cipher: {cipher}"
                )
            else:
                QMessageBox.warning(
                    self, "No Tunnel",
                    "Connect to a tunnel server first "
                    "(Tunnel Client tab).",
                )

    def _detach_tunnel(self):
        self.attach_tunnel_session(None)
        self.bridge.status_update.emit("Proxy detached — direct mode")

    def attach_tunnel_session(self, session: Session | None):
        if self.proxy_server:
            self.proxy_server.tunnel_session = session
            if session:
                self.logger.info(
                    "Proxy using tunnel cipher: %s", session.cipher
                )
            else:
                self.logger.info("Proxy switched to direct mode")

    def _set_system_proxy(self):
        host = self.txt_host.text().strip()
        port = self.spn_port.value()
        success, msg = SystemProxyConfig.enable_system_proxy(
            host, port
        )
        icon = "✅" if success else "❌"
        QMessageBox.information(self, "System Proxy", f"{icon} {msg}")
        self.bridge.status_update.emit(msg)

    def _unset_system_proxy(self):
        success, msg = SystemProxyConfig.disable_system_proxy()
        QMessageBox.information(self, "System Proxy", msg)
        self.bridge.status_update.emit(msg)

    def _block_domain(self):
        domain = self.txt_block.text().strip()
        if domain and self.proxy_server:
            self.proxy_server.add_blocked_domain(domain)
            self.txt_block.clear()
            self.bridge.status_update.emit(f"Blocked: {domain}")

    def _unblock_domain(self):
        domain = self.txt_block.text().strip()
        if domain and self.proxy_server:
            self.proxy_server.remove_blocked_domain(domain)
            self.txt_block.clear()
            self.bridge.status_update.emit(f"Unblocked: {domain}")

    def _cb_request(self, method: str, host: str, port: int):
        self.bridge.proxy_request.emit(method, host, port)

    def _on_proxy_request(self, method: str, host: str, port: int):
        ts = datetime.now().strftime("%H:%M:%S")
        encrypted = "🔒"
        cipher_tag = ""
        if (
            self.proxy_server
            and self.proxy_server.tunnel_session
            and self.proxy_server.tunnel_session.active
        ):
            cipher_tag = f" [{self.proxy_server.tunnel_session.cipher}]"
        else:
            encrypted = "🔓"
        self.txt_log.appendPlainText(
            f"[{ts}] {encrypted} {method:8s} {host}:{port}{cipher_tag}"
        )

    def _refresh_stats(self):
        if self.proxy_server and self.proxy_server.is_running:
            stats = self.proxy_server.stats()
            self.lbl_requests.setText(str(stats["total_requests"]))
            self.lbl_active.setText(str(stats["active_connections"]))
            self.lbl_blocked.setText(str(stats["blocked_requests"]))
            self.lbl_mode.setText(stats["mode"])

            if stats["tunnel_active"]:
                cipher = stats.get("tunnel_cipher", "Unknown")
                details = stats.get("tunnel_cipher_info", {})
                self.lbl_cipher.setText(f"🔒 {cipher}")
                self.lbl_cipher_bits.setText(
                    f"{details.get('key_bits', '?')}-bit"
                )
                aead = details.get("aead", False)
                self.lbl_cipher_aead.setText(
                    "🛡️ Built-in (AEAD)" if aead
                    else "🔗 HMAC-SHA256"
                )
            else:
                self.lbl_cipher.setText("🔓 No encryption (direct)")
                self.lbl_cipher_bits.setText("—")
                self.lbl_cipher_aead.setText("—")

    @property
    def is_running(self) -> bool:
        return (
            self.proxy_server is not None
            and self.proxy_server.is_running
        )

    @property
    def active_cipher(self) -> str | None:
        if (
            self.proxy_server
            and self.proxy_server.tunnel_session
            and self.proxy_server.tunnel_session.active
        ):
            return self.proxy_server.tunnel_session.cipher
        return None

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tab 5 — E2E Messaging
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# class E2EMessagingTab(QWidget):
#     """
#     Full E2E encrypted messaging and file transfer tab.

#     Sections:
#     1. Relay connection + registration
#     2. Peer discovery + E2E session setup
#     3. Chat area (send/receive messages)
#     4. File transfer (send/receive files)
#     5. Security info (fingerprints, cipher details)
#     """

#     def __init__(self, bridge: SignalBridge, parent=None):
#         super().__init__(parent)
#         self.bridge = bridge
#         self.peer_client: PeerClient | None = None
#         self.relay_server: RelayServer | None = None
#         self._peer_list: list[dict] = []
#         self._build_ui()

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         # ━━━ Connection Section ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#         conn_group = QGroupBox("🔗 Relay Connection")
#         conn_layout = QGridLayout(conn_group)

#         conn_layout.addWidget(QLabel("Username:"), 0, 0)
#         self.txt_username = QLineEdit("alice")
#         conn_layout.addWidget(self.txt_username, 0, 1)

#         conn_layout.addWidget(QLabel("Relay Host:"), 0, 2)
#         self.txt_relay_host = QLineEdit("127.0.0.1")
#         conn_layout.addWidget(self.txt_relay_host, 0, 3)

#         conn_layout.addWidget(QLabel("Relay Port:"), 0, 4)
#         self.spn_relay_port = QSpinBox()
#         self.spn_relay_port.setRange(1, 65535)
#         self.spn_relay_port.setValue(9091)
#         conn_layout.addWidget(self.spn_relay_port, 0, 5)

#         btn_row = QHBoxLayout()
#         self.btn_start_relay = QPushButton("🖥️ Start Relay Server")
#         self.btn_start_relay.clicked.connect(self._start_relay)
#         btn_row.addWidget(self.btn_start_relay)

#         self.btn_connect = QPushButton("🔗 Connect & Register")
#         self.btn_connect.clicked.connect(self._connect)
#         btn_row.addWidget(self.btn_connect)

#         self.btn_disconnect = QPushButton("❌ Disconnect")
#         self.btn_disconnect.setProperty("danger", True)
#         self.btn_disconnect.setEnabled(False)
#         self.btn_disconnect.clicked.connect(self._disconnect)
#         btn_row.addWidget(self.btn_disconnect)

#         conn_layout.addLayout(btn_row, 1, 0, 1, 6)

#         self.lbl_identity = QLabel("Identity: Not generated")
#         self.lbl_identity.setStyleSheet("color: #6c7086;")
#         conn_layout.addWidget(self.lbl_identity, 2, 0, 1, 6)

#         layout.addWidget(conn_group)

#         # ━━━ Peer & E2E Session ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#         peer_group = QGroupBox("👥 Peers & E2E Sessions")
#         peer_layout = QHBoxLayout(peer_group)

#         # Peer list
#         peer_left = QVBoxLayout()
#         peer_left.addWidget(QLabel("Online Peers:"))
#         self.lst_peers = QListWidget()
#         self.lst_peers.setMaximumHeight(120)
#         peer_left.addWidget(self.lst_peers)

#         peer_btn_row = QHBoxLayout()
#         self.btn_refresh_peers = QPushButton("🔄 Refresh")
#         self.btn_refresh_peers.clicked.connect(self._refresh_peers)
#         peer_btn_row.addWidget(self.btn_refresh_peers)
#         peer_left.addLayout(peer_btn_row)
#         peer_layout.addLayout(peer_left)

#         # E2E setup
#         peer_right = QVBoxLayout()
#         peer_right.addWidget(QLabel("Cipher for E2E:"))
#         self.cmb_e2e_cipher = QComboBox()
#         self.cmb_e2e_cipher.addItems(CipherFactory.list_ciphers())
#         peer_right.addWidget(self.cmb_e2e_cipher)

#         self.btn_init_e2e = QPushButton("🔐 Establish E2E Session")
#         self.btn_init_e2e.clicked.connect(self._init_e2e)
#         peer_right.addWidget(self.btn_init_e2e)

#         self.lbl_session = QLabel("No active E2E session")
#         self.lbl_session.setStyleSheet("color: #f9e2af;")
#         self.lbl_session.setWordWrap(True)
#         peer_right.addWidget(self.lbl_session)

#         peer_layout.addLayout(peer_right)
#         layout.addWidget(peer_group)

#         # ━━━ Chat Area ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#         chat_group = QGroupBox("💬 Encrypted Chat")
#         chat_layout = QVBoxLayout(chat_group)

#         self.txt_chat = QPlainTextEdit()
#         self.txt_chat.setReadOnly(True)
#         self.txt_chat.setMaximumBlockCount(1000)
#         chat_layout.addWidget(self.txt_chat)

#         msg_row = QHBoxLayout()
#         self.txt_msg = QLineEdit()
#         self.txt_msg.setPlaceholderText("Type a message…")
#         self.txt_msg.returnPressed.connect(self._send_message)
#         msg_row.addWidget(self.txt_msg)

#         self.btn_send = QPushButton("📤 Send")
#         self.btn_send.clicked.connect(self._send_message)
#         msg_row.addWidget(self.btn_send)

#         chat_layout.addLayout(msg_row)
#         layout.addWidget(chat_group)

#         # ━━━ File Transfer ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#         file_group = QGroupBox("📁 Encrypted File Transfer")
#         file_layout = QHBoxLayout(file_group)

#         self.btn_send_file = QPushButton("📤 Send File")
#         self.btn_send_file.clicked.connect(self._send_file)
#         file_layout.addWidget(self.btn_send_file)

#         self.lbl_file_status = QLabel("No transfer in progress")
#         self.lbl_file_status.setWordWrap(True)
#         file_layout.addWidget(self.lbl_file_status)

#         layout.addWidget(file_group)

#         # ━━━ Security Info ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#         sec_group = QGroupBox("🛡️ Security Verification")
#         sec_layout = QVBoxLayout(sec_group)

#         self.txt_security = QPlainTextEdit()
#         self.txt_security.setReadOnly(True)
#         self.txt_security.setMaximumHeight(80)
#         self.txt_security.setFont(MONO_FONT)
#         sec_layout.addWidget(self.txt_security)

#         layout.addWidget(sec_group)

#     # ── Relay Server ─────────────────────────────────────────────

#     def _start_relay(self):
#         try:
#             port = self.spn_relay_port.value()
#             self.relay_server = RelayServer("0.0.0.0", port)
#             self.relay_server.start()
#             self.btn_start_relay.setEnabled(False)
#             self.bridge.status_update.emit(
#                 f"Relay server started on port {port}"
#             )
#         except Exception as exc:
#             QMessageBox.critical(self, "Error", str(exc))

#     # ── Connection ───────────────────────────────────────────────

#     def _connect(self):
#         username = self.txt_username.text().strip()
#         if not username:
#             QMessageBox.warning(self, "Error", "Enter a username")
#             return

#         def _do():
#             self.peer_client = PeerClient(
#                 username=username,
#                 relay_host=self.txt_relay_host.text().strip(),
#                 relay_port=self.spn_relay_port.value(),
#                 on_message_received=self._cb_message,
#                 on_file_started=self._cb_file_start,
#                 on_file_progress=self._cb_file_progress,
#                 on_file_complete=self._cb_file_complete,
#                 on_peer_list=self._cb_peers,
#                 on_e2e_established=self._cb_e2e,
#                 on_status=lambda m: self.bridge.status_update.emit(m),
#                 on_error=lambda m: self.bridge.status_update.emit(f"⚠️ {m}"),
#             )
#             if self.peer_client.connect():
#                 self.bridge.status_update.emit(
#                     f"Registered as '{username}'"
#                 )

#         threading.Thread(target=_do, daemon=True).start()
#         self.btn_connect.setEnabled(False)
#         self.btn_disconnect.setEnabled(True)

#         # Show identity
#         QTimer.singleShot(2000, self._update_identity)

#     def _update_identity(self):
#         if self.peer_client and self.peer_client.identity_info:
#             info = self.peer_client.identity_info
#             self.lbl_identity.setText(
#                 f"🔑 Identity: {info['username']} | "
#                 f"RSA-{info['key_size']} | "
#                 f"Fingerprint: {info['fingerprint'][:24]}…"
#             )
#             self.txt_security.setPlainText(
#                 f"Your fingerprint:\n{info['fingerprint']}\n\n"
#                 f"Share this with your peers to verify identity "
#                 f"(like WhatsApp security code)."
#             )

#     def _disconnect(self):
#         if self.peer_client:
#             self.peer_client.disconnect()
#             self.peer_client = None
#         if self.relay_server:
#             self.relay_server.stop()
#             self.relay_server = None
#             self.btn_start_relay.setEnabled(True)
#         self.btn_connect.setEnabled(True)
#         self.btn_disconnect.setEnabled(False)
#         self.lbl_identity.setText("Identity: Not connected")

#     # ── Peer Discovery ───────────────────────────────────────────

#     def _refresh_peers(self):
#         if self.peer_client and self.peer_client.is_connected:
#             self.peer_client.request_peer_list()

#     def _cb_peers(self, peers: list[dict]):
#         self._peer_list = peers
#         self.lst_peers.clear()
#         for p in peers:
#             status = "🟢" if p["online"] else "⚫"
#             self.lst_peers.addItem(
#                 f"{status} {p['username']}"
#             )

#     # ── E2E Session ──────────────────────────────────────────────

#     def _init_e2e(self):
#         if not self.peer_client or not self.peer_client.is_connected:
#             QMessageBox.warning(self, "Error", "Connect first")
#             return

#         item = self.lst_peers.currentItem()
#         if not item:
#             QMessageBox.warning(self, "Error", "Select a peer")
#             return

#         peer_name = item.text().split(" ", 1)[1]   # remove emoji
#         cipher = self.cmb_e2e_cipher.currentText()

#         # Find peer's RSA public key
#         peer_data = next(
#             (p for p in self._peer_list if p["username"] == peer_name),
#             None,
#         )
#         if not peer_data or "rsa_public_key" not in peer_data:
#             QMessageBox.warning(
#                 self, "Error",
#                 "Peer public key not available. Refresh peer list.",
#             )
#             return

#         def _do():
#             self.peer_client.initiate_e2e(
#                 peer_name, peer_data["rsa_public_key"], cipher
#             )

#         threading.Thread(target=_do, daemon=True).start()

#     def _cb_e2e(self, peer_username: str, session_info: dict):
#         cipher = session_info.get("cipher", "?")
#         ci = session_info.get("cipher_info", {})
#         fp = session_info.get("peer_fingerprint", "?")

#         self.lbl_session.setText(
#             f"🔒 E2E with {peer_username}\n"
#             f"Cipher: {cipher} ({ci.get('key_bits', '?')}-bit, "
#             f"{'AEAD' if ci.get('aead') else 'HMAC'})\n"
#             f"Peer fingerprint: {fp[:24]}…"
#         )
#         self.txt_security.appendPlainText(
#             f"\nPeer '{peer_username}' fingerprint:\n{fp}"
#         )
#         self._chat_system(
#             f"🔐 E2E session established with {peer_username} "
#             f"using {cipher}"
#         )

#     # ── Messaging ────────────────────────────────────────────────

#     def _send_message(self):
#         if not self.peer_client:
#             return
#         text = self.txt_msg.text().strip()
#         if not text:
#             return

#         item = self.lst_peers.currentItem()
#         if not item:
#             QMessageBox.warning(self, "Error", "Select a peer")
#             return

#         peer_name = item.text().split(" ", 1)[1]

#         def _do():
#             self.peer_client.send_message(peer_name, text)

#         threading.Thread(target=_do, daemon=True).start()

#         # Show in chat
#         ts = datetime.now().strftime("%H:%M:%S")
#         self.txt_chat.appendPlainText(
#             f"[{ts}] 📤 You → {peer_name}: {text}"
#         )
#         self.txt_msg.clear()

#     def _cb_message(self, from_user: str, text: str,
#                     sig_valid: bool, timestamp: float,
#                     cipher: str):
#         ts = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
#         sig_icon = "✅" if sig_valid else "❌ UNVERIFIED"
#         self.txt_chat.appendPlainText(
#             f"[{ts}] 📩 {from_user}: {text}\n"
#             f"        {sig_icon} | 🔒 {cipher}"
#         )

#     # ── File Transfer ────────────────────────────────────────────

#     def _send_file(self):
#         if not self.peer_client:
#             return

#         item = self.lst_peers.currentItem()
#         if not item:
#             QMessageBox.warning(self, "Error", "Select a peer")
#             return

#         peer_name = item.text().split(" ", 1)[1]

#         filepath, _ = QFileDialog.getOpenFileName(
#             self, "Select File to Send"
#         )
#         if not filepath:
#             return

#         def _do():
#             def _progress(p):
#                 self.lbl_file_status.setText(
#                     f"Sending… {p * 100:.0f}%"
#                 )

#             success = self.peer_client.send_file(
#                 peer_name, filepath, progress_callback=_progress
#             )
#             if success:
#                 self._chat_system(
#                     f"📤 File sent to {peer_name}: "
#                     f"{os.path.basename(filepath)}"
#                 )

#         threading.Thread(target=_do, daemon=True).start()

#     def _cb_file_start(self, from_user: str, meta: dict):
#         self._chat_system(
#             f"📩 Receiving file from {from_user}: "
#             f"{meta['filename']} "
#             f"({FileMetadata.format_size(meta['file_size'])})"
#         )

#     def _cb_file_progress(self, transfer_id: str, progress: float):
#         self.lbl_file_status.setText(
#             f"Receiving… {progress * 100:.0f}%"
#         )

#     def _cb_file_complete(self, from_user: str, result: dict):
#         if result["success"]:
#             self._chat_system(
#                 f"✅ File from {from_user}: {result['filename']}\n"
#                 f"   Hash: ✅ verified | Signature: ✅ verified\n"
#                 f"   Saved: {result['path']}"
#             )
#             self.lbl_file_status.setText(
#                 f"✅ {result['filename']} received"
#             )
#         else:
#             h = "✅" if result["hash_valid"] else "❌"
#             s = "✅" if result["sig_valid"] else "❌"
#             self._chat_system(
#                 f"❌ File from {from_user}: VERIFICATION FAILED\n"
#                 f"   Hash: {h} | Signature: {s}"
#             )
#             self.lbl_file_status.setText("❌ File verification failed")

#     def _chat_system(self, msg: str):
#         ts = datetime.now().strftime("%H:%M:%S")
#         self.txt_chat.appendPlainText(f"[{ts}] ℹ️ {msg}")



"""
CORRECTED E2EMessagingTab — Drop-in replacement for the class in main.py

FIXES:
  1. Shows local IP address so Laptop B knows what to connect to
  2. "Start Relay" auto-fills relay host with 0.0.0.0 / shows LAN IP
  3. Auto-refreshes peer list after connecting (3-second delay)
  4. Periodic peer list refresh every 10 seconds
  5. "Copy IP" button for easy sharing
  6. Clear setup instructions in the UI
"""





class E2EMessagingTab(QWidget):
    """
    Full E2E encrypted messaging and file transfer tab.

    TWO-LAPTOP SETUP
    ────────────────
    Laptop A (relay host):
        1. Click "▶ Start Relay Server"   ← binds 0.0.0.0:9091
        2. Share the IP shown in the green banner with Laptop B
        3. Click "⚡ Connect & Register"

    Laptop B (remote peer):
        1. Enter Laptop A's IP in "Relay Host"
        2. Change Username
        3. Click "⚡ Connect & Register"
        4. Click "🔄 Refresh Peers" — Laptop A appears
        5. Select Laptop A, choose cipher, click "🔐 Establish E2E Session"
    """

    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.peer_client: PeerClient | None = None
        self.relay_server: RelayServer | None = None
        self._peer_list: list[dict] = []
        self._peer_refresh_timer = QTimer(self)
        self._peer_refresh_timer.timeout.connect(self._refresh_peers)
        self._build_ui()

    # ── UI Construction ────────────────────────────────────────────────────────

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # ── 0. Local IP Banner ─────────────────────────────────────────────
        local_ip = _get_local_ip()
        ip_banner = QGroupBox("📡 Your LAN IP — share this with the other laptop")
        ip_layout = QHBoxLayout(ip_banner)
        ip_banner.setStyleSheet(
            "QGroupBox { border: 1px solid #a6e3a1; color: #a6e3a1; }"
        )

        self.lbl_local_ip = QLabel(f"  {local_ip}  ")
        self.lbl_local_ip.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        self.lbl_local_ip.setStyleSheet(
            "color: #a6e3a1; background: #1e3a2e; "
            "border-radius: 6px; padding: 4px 12px;"
        )
        ip_layout.addWidget(self.lbl_local_ip)

        btn_copy_ip = QPushButton("📋 Copy IP")
        btn_copy_ip.setFixedWidth(100)
        btn_copy_ip.clicked.connect(
            lambda: QApplication.clipboard().setText(local_ip)
        )
        ip_layout.addWidget(btn_copy_ip)
        ip_layout.addStretch()

        # Quick setup instructions
        instructions = QLabel(
            "<b>Laptop A:</b> Start Relay → Connect &nbsp;|&nbsp; "
            "<b>Laptop B:</b> Enter Laptop A's IP above → Connect → Refresh Peers → E2E Session"
        )
        instructions.setStyleSheet("color: #cba6f7; font-size: 11px; padding: 2px 8px;")
        ip_layout.addWidget(instructions)

        layout.addWidget(ip_banner)

        # ── 1. Connection Section ──────────────────────────────────────────
        conn_group = QGroupBox("🔗 Relay Connection")
        conn_layout = QGridLayout(conn_group)

        conn_layout.addWidget(QLabel("Username:"), 0, 0)
        self.txt_username = QLineEdit("alice")
        conn_layout.addWidget(self.txt_username, 0, 1)

        conn_layout.addWidget(QLabel("Relay Host:"), 0, 2)
        self.txt_relay_host = QLineEdit("127.0.0.1")
        self.txt_relay_host.setPlaceholderText("Laptop A's IP  e.g. 192.168.1.10")
        conn_layout.addWidget(self.txt_relay_host, 0, 3)

        conn_layout.addWidget(QLabel("Relay Port:"), 0, 4)
        self.spn_relay_port = QSpinBox()
        self.spn_relay_port.setRange(1, 65535)
        self.spn_relay_port.setValue(9091)
        conn_layout.addWidget(self.spn_relay_port, 0, 5)

        btn_row = QHBoxLayout()

        self.btn_start_relay = QPushButton("▶ Start Relay Server")
        self.btn_start_relay.setToolTip(
            "Run this on ONE laptop only (the one others connect to)"
        )
        self.btn_start_relay.clicked.connect(self._start_relay)
        btn_row.addWidget(self.btn_start_relay)

        self.btn_connect = QPushButton("⚡ Connect & Register")
        self.btn_connect.clicked.connect(self._connect)
        btn_row.addWidget(self.btn_connect)

        self.btn_disconnect = QPushButton("✖ Disconnect")
        self.btn_disconnect.setProperty("danger", True)
        self.btn_disconnect.setEnabled(False)
        self.btn_disconnect.clicked.connect(self._disconnect)
        btn_row.addWidget(self.btn_disconnect)

        conn_layout.addLayout(btn_row, 1, 0, 1, 6)

        self.lbl_conn_status = QLabel("● Not connected")
        self.lbl_conn_status.setStyleSheet("color: #f38ba8; padding: 2px 4px;")
        conn_layout.addWidget(self.lbl_conn_status, 2, 0, 1, 4)

        self.lbl_identity = QLabel("Identity: Not generated")
        self.lbl_identity.setStyleSheet("color: #6c7086;")
        conn_layout.addWidget(self.lbl_identity, 3, 0, 1, 6)

        layout.addWidget(conn_group)

        # ── 2. Peer & E2E Session ──────────────────────────────────────────
        peer_group = QGroupBox("👥 Peers & E2E Sessions")
        peer_layout = QHBoxLayout(peer_group)

        # Peer list (left side)
        peer_left = QVBoxLayout()

        self.lbl_peer_count = QLabel("Online Peers: (not connected)")
        self.lbl_peer_count.setStyleSheet("color: #6c7086; font-size: 11px;")
        peer_left.addWidget(self.lbl_peer_count)

        self.lst_peers = QListWidget()
        self.lst_peers.setMaximumHeight(120)
        self.lst_peers.setToolTip("Double-click a peer to start E2E session")
        self.lst_peers.itemDoubleClicked.connect(self._on_peer_double_click)
        peer_left.addWidget(self.lst_peers)

        peer_btn_row = QHBoxLayout()
        self.btn_refresh_peers = QPushButton("🔄 Refresh Peers")
        self.btn_refresh_peers.clicked.connect(self._refresh_peers)
        peer_btn_row.addWidget(self.btn_refresh_peers)
        peer_left.addLayout(peer_btn_row)

        peer_layout.addLayout(peer_left, 2)

        # E2E setup (right side)
        peer_right = QVBoxLayout()
        peer_right.addWidget(QLabel("Cipher for E2E:"))
        self.cmb_e2e_cipher = QComboBox()
        self.cmb_e2e_cipher.addItems(CipherFactory.list_ciphers())
        peer_right.addWidget(self.cmb_e2e_cipher)

        self.btn_init_e2e = QPushButton("🔐 Establish E2E Session")
        self.btn_init_e2e.clicked.connect(self._init_e2e)
        peer_right.addWidget(self.btn_init_e2e)

        self.lbl_session = QLabel("No active E2E session")
        self.lbl_session.setStyleSheet("color: #f9e2af;")
        self.lbl_session.setWordWrap(True)
        peer_right.addWidget(self.lbl_session)

        peer_layout.addLayout(peer_right, 1)
        layout.addWidget(peer_group)

        # ── 3. Chat Area ───────────────────────────────────────────────────
        chat_group = QGroupBox("💬 Encrypted Chat")
        chat_layout = QVBoxLayout(chat_group)

        self.txt_chat = QPlainTextEdit()
        self.txt_chat.setReadOnly(True)
        self.txt_chat.setMaximumBlockCount(1000)
        chat_layout.addWidget(self.txt_chat)

        msg_row = QHBoxLayout()
        self.txt_msg = QLineEdit()
        self.txt_msg.setPlaceholderText("Type a message… (need E2E session first)")
        self.txt_msg.returnPressed.connect(self._send_message)
        msg_row.addWidget(self.txt_msg)

        self.btn_send = QPushButton("📤 Send")
        self.btn_send.clicked.connect(self._send_message)
        msg_row.addWidget(self.btn_send)
        chat_layout.addLayout(msg_row)

        layout.addWidget(chat_group)

        # ── 4. File Transfer ───────────────────────────────────────────────
        file_group = QGroupBox("📁 Encrypted File Transfer")
        file_layout = QHBoxLayout(file_group)

        self.btn_send_file = QPushButton("📤 Send File")
        self.btn_send_file.clicked.connect(self._send_file)
        file_layout.addWidget(self.btn_send_file)

        self.lbl_file_status = QLabel("No transfer in progress")
        self.lbl_file_status.setWordWrap(True)
        file_layout.addWidget(self.lbl_file_status)

        layout.addWidget(file_group)

        # ── 5. Security Info ───────────────────────────────────────────────
        sec_group = QGroupBox("🔒 Security Verification")
        sec_layout = QVBoxLayout(sec_group)

        self.txt_security = QPlainTextEdit()
        self.txt_security.setReadOnly(True)
        self.txt_security.setMaximumHeight(80)
        self.txt_security.setFont(MONO_FONT)
        self.txt_security.setPlaceholderText(
            "Your RSA fingerprint will appear here after connecting.\n"
            "Share it with your peer to verify identity (like WhatsApp security code)."
        )
        sec_layout.addWidget(self.txt_security)

        layout.addWidget(sec_group)

    # ── Relay Server ───────────────────────────────────────────────────────────

    def _start_relay(self):
        """
        FIX: After starting the relay, auto-fill relay host with the local
        LAN IP so the "Connect" button connects to the right place.
        Previously it stayed as 127.0.0.1, which only worked locally.
        """
        try:
            port = self.spn_relay_port.value()
            self.relay_server = RelayServer("0.0.0.0", port)
            self.relay_server.start()
            self.btn_start_relay.setEnabled(False)
            self.btn_start_relay.setText("✅ Relay Running")

            # FIX: update the relay host field to the actual LAN IP
            local_ip = _get_local_ip()
            self.txt_relay_host.setText(local_ip)

            self.bridge.status_update.emit(
                f"Relay server started on {local_ip}:{port} — "
                f"tell the other laptop to connect to this IP"
            )
            self._chat_system(
                f"📡 Relay server started. Share this IP with the other laptop: "
                f"{local_ip}:{port}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    # ── Connection ─────────────────────────────────────────────────────────────

    def _connect(self):
        username = self.txt_username.text().strip()
        if not username:
            QMessageBox.warning(self, "Error", "Enter a username")
            return

        relay_host = self.txt_relay_host.text().strip()
        relay_port = self.spn_relay_port.value()

        self.lbl_conn_status.setText("● Connecting…")
        self.lbl_conn_status.setStyleSheet("color: #f9e2af; padding: 2px 4px;")

        def _do():
            self.peer_client = PeerClient(
                username=username,
                relay_host=relay_host,
                relay_port=relay_port,
                on_message_received=self._cb_message,
                on_file_started=self._cb_file_start,
                on_file_progress=self._cb_file_progress,
                on_file_complete=self._cb_file_complete,
                on_peer_list=self._cb_peers,
                on_e2e_established=self._cb_e2e,
                on_status=lambda m: self.bridge.status_update.emit(m),
                on_error=lambda m: self.bridge.status_update.emit(f"⚠️ {m}"),
            )
            if self.peer_client.connect():
                # Update UI on main thread
                self.lbl_conn_status.setText(
                    f"● Connected as '{username}' → {relay_host}:{relay_port}"
                )
                self.lbl_conn_status.setStyleSheet(
                    "color: #a6e3a1; padding: 2px 4px;"
                )
                self.bridge.status_update.emit(
                    f"Registered as '{username}' on {relay_host}:{relay_port}"
                )
                # FIX: auto-refresh identity and peer list after connecting
                QTimer.singleShot(1500, self._update_identity)
                QTimer.singleShot(3000, self._refresh_peers)
                # FIX: start periodic peer refresh so new peers appear automatically
                self._peer_refresh_timer.start(10_000)   # every 10 seconds
            else:
                self.lbl_conn_status.setText(
                    f"● Failed to connect to {relay_host}:{relay_port}"
                )
                self.lbl_conn_status.setStyleSheet(
                    "color: #f38ba8; padding: 2px 4px;"
                )
                self.btn_connect.setEnabled(True)
                self.btn_disconnect.setEnabled(False)

        threading.Thread(target=_do, daemon=True).start()
        self.btn_connect.setEnabled(False)
        self.btn_disconnect.setEnabled(True)

    def _update_identity(self):
        if self.peer_client and self.peer_client.identity_info:
            info = self.peer_client.identity_info
            self.lbl_identity.setText(
                f"✅ Identity: {info['username']} | "
                f"RSA-{info['key_size']} | "
                f"Fingerprint: {info['fingerprint'][:24]}…"
            )
            self.txt_security.setPlainText(
                f"Your fingerprint:\n{info['fingerprint']}\n\n"
                f"Share this with your peers to verify identity "
                f"(like WhatsApp security code)."
            )

    def _disconnect(self):
        self._peer_refresh_timer.stop()       # FIX: stop periodic refresh
        if self.peer_client:
            self.peer_client.disconnect()
            self.peer_client = None
        if self.relay_server:
            self.relay_server.stop()
            self.relay_server = None
            self.btn_start_relay.setEnabled(True)
            self.btn_start_relay.setText("▶ Start Relay Server")
        self.btn_connect.setEnabled(True)
        self.btn_disconnect.setEnabled(False)
        self.lbl_conn_status.setText("● Not connected")
        self.lbl_conn_status.setStyleSheet("color: #f38ba8; padding: 2px 4px;")
        self.lbl_identity.setText("Identity: Not connected")
        self.lst_peers.clear()
        self.lbl_peer_count.setText("Online Peers: (not connected)")
        self.bridge.status_update.emit("Disconnected")

    # ── Peer Discovery ─────────────────────────────────────────────────────────

    def _refresh_peers(self):
        if self.peer_client and self.peer_client.is_connected:
            self.peer_client.request_peer_list()

    def _cb_peers(self, peers: list[dict]):
        self._peer_list = peers
        self.lst_peers.clear()
        online = [p for p in peers if p.get("online", True)]
        self.lbl_peer_count.setText(
            f"Online Peers: {len(online)} found"
        )
        for p in peers:
            status = "🟢" if p.get("online", True) else "🔴"
            self.lst_peers.addItem(f"{status} {p['username']}")
        if not peers:
            self.lst_peers.addItem("(no peers online yet — ask them to connect)")

    def _on_peer_double_click(self, item):
        """Double-clicking a peer auto-initiates E2E session."""
        self._init_e2e()

    # ── E2E Session ───────────────────────────────────────────────────────────

    def _init_e2e(self):
        if not self.peer_client or not self.peer_client.is_connected:
            QMessageBox.warning(self, "Error", "Connect to the relay first")
            return

        item = self.lst_peers.currentItem()
        if not item:
            QMessageBox.warning(self, "Error", "Select a peer from the list")
            return

        raw_text = item.text()
        # Strip the leading emoji + space  e.g. "🟢 alice" → "alice"
        parts = raw_text.split(" ", 1)
        if len(parts) < 2:
            QMessageBox.warning(self, "Error", "Could not parse peer name")
            return
        peer_name = parts[1].strip()

        if not peer_name or peer_name.startswith("("):
            QMessageBox.warning(self, "Error", "Select a valid online peer")
            return

        cipher = self.cmb_e2e_cipher.currentText()

        # Look up this peer's RSA public key from the last-fetched list
        peer_data = next(
            (p for p in self._peer_list if p["username"] == peer_name),
            None,
        )
        if not peer_data:
            QMessageBox.warning(
                self, "Error",
                f"Peer '{peer_name}' not in peer list.\n"
                f"Click 🔄 Refresh Peers first.",
            )
            return

        if "rsa_public_key" not in peer_data:
            QMessageBox.warning(
                self, "Error",
                "Peer public key not available.\n"
                "Click 🔄 Refresh Peers to fetch it.",
            )
            return

        self.lbl_session.setText(
            f"⏳ Establishing E2E session with {peer_name}…"
        )

        def _do():
            self.peer_client.initiate_e2e(
                peer_name, peer_data["rsa_public_key"], cipher
            )

        threading.Thread(target=_do, daemon=True).start()

    def _cb_e2e(self, peer_username: str, session_info: dict):
        cipher = session_info.get("cipher", "?")
        ci = session_info.get("cipher_info", {})
        fp = session_info.get("peer_fingerprint", "?")
        self.lbl_session.setText(
            f"✅ E2E with {peer_username}\n"
            f"Cipher: {cipher} ({ci.get('key_bits', '?')}-bit, "
            f"{'AEAD' if ci.get('aead') else 'HMAC'})\n"
            f"Peer fingerprint: {fp[:24]}…"
        )
        self.txt_security.appendPlainText(
            f"\nPeer '{peer_username}' fingerprint:\n{fp}"
        )
        self._chat_system(
            f"✅ E2E session established with {peer_username} using {cipher}"
        )

    # ── Messaging ──────────────────────────────────────────────────────────────

    def _send_message(self):
        if not self.peer_client:
            return
        text = self.txt_msg.text().strip()
        if not text:
            return

        item = self.lst_peers.currentItem()
        if not item:
            QMessageBox.warning(self, "Error", "Select a peer to send to")
            return

        raw_text = item.text()
        parts = raw_text.split(" ", 1)
        if len(parts) < 2:
            return
        peer_name = parts[1].strip()

        def _do():
            self.peer_client.send_message(peer_name, text)

        threading.Thread(target=_do, daemon=True).start()

        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_chat.appendPlainText(
            f"[{ts}] 📤 You → {peer_name}: {text}"
        )
        self.txt_msg.clear()

    def _cb_message(self, from_user: str, text: str,
                     sig_valid: bool, timestamp: float, cipher: str):
        ts = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
        sig_icon = "✅" if sig_valid else "⚠️ UNVERIFIED"
        self.txt_chat.appendPlainText(
            f"[{ts}] 📨 {from_user}: {text}\n"
            f"         {sig_icon} | 🔒 {cipher}"
        )

    # ── File Transfer ──────────────────────────────────────────────────────────

    def _send_file(self):
        if not self.peer_client:
            return
        item = self.lst_peers.currentItem()
        if not item:
            QMessageBox.warning(self, "Error", "Select a peer")
            return

        raw_text = item.text()
        parts = raw_text.split(" ", 1)
        if len(parts) < 2:
            return
        peer_name = parts[1].strip()

        filepath, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if not filepath:
            return

        def _do():
            def _progress(p):
                self.lbl_file_status.setText(f"Sending… {p * 100:.0f}%")

            success = self.peer_client.send_file(
                peer_name, filepath, progress_callback=_progress
            )
            if success:
                self._chat_system(
                    f"✅ File sent to {peer_name}: {os.path.basename(filepath)}"
                )

        threading.Thread(target=_do, daemon=True).start()

    def _cb_file_start(self, from_user: str, meta: dict):
        self._chat_system(
            f"📥 Receiving file from {from_user}: "
            f"{meta['filename']} "
            f"({FileMetadata.format_size(meta['file_size'])})"
        )

    def _cb_file_progress(self, transfer_id: str, progress: float):
        self.lbl_file_status.setText(f"Receiving… {progress * 100:.0f}%")

    def _cb_file_complete(self, from_user: str, result: dict):
        if result["success"]:
            self._chat_system(
                f"✅ File from {from_user}: {result['filename']}\n"
                f"   Hash: ✅ verified | Signature: ✅ verified\n"
                f"   Saved: {result['path']}"
            )
            self.lbl_file_status.setText(f"✅ {result['filename']} received")
        else:
            h = "✅" if result["hash_valid"] else "❌"
            s = "✅" if result["sig_valid"] else "❌"
            self._chat_system(
                f"❌ File from {from_user}: VERIFICATION FAILED\n"
                f"   Hash: {h} | Signature: {s}"
            )
            self.lbl_file_status.setText("❌ File verification failed")

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _chat_system(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_chat.appendPlainText(f"[{ts}] 🔧 {msg}")



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tab 6 — Crypto Tools
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
#  Tab 7 — Key Manager
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
#  Tab 8 — Logs
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
#  Tab 9 — Cipher Selector
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class CipherSelectorWidget(QGroupBox):
    """
    Reusable widget that shows all available ciphers with
    checkboxes + a preferred-cipher dropdown.

    Used in TunnelServerTab, TunnelClientTab, and ProxyTab.
    """

    cipher_changed = pyqtSignal()   # emitted when selection changes

    def __init__(self, title: str = "Cipher Selection",
                 parent=None):
        super().__init__(title, parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # ── Preferred cipher dropdown ────────────────────────────
        pref_row = QHBoxLayout()
        pref_row.addWidget(QLabel("Preferred Cipher:"))
        self.cmb_preferred = QComboBox()
        self.cmb_preferred.addItems(CipherFactory.list_ciphers())
        self.cmb_preferred.setCurrentText("AES-256-GCM")
        self.cmb_preferred.currentTextChanged.connect(
            self._on_preferred_changed
        )
        pref_row.addWidget(self.cmb_preferred)

        # Info label
        self.lbl_info = QLabel("")
        self.lbl_info.setStyleSheet("color: #6c7086; font-size: 11px;")
        pref_row.addWidget(self.lbl_info)

        layout.addLayout(pref_row)

        # ── Quick-select buttons ─────────────────────────────────
        btn_row = QHBoxLayout()

        btn_all = QPushButton("Select All")
        btn_all.clicked.connect(self._select_all)
        btn_row.addWidget(btn_all)

        btn_aead = QPushButton("AEAD Only")
        btn_aead.clicked.connect(self._select_aead_only)
        btn_row.addWidget(btn_aead)

        btn_fast = QPushButton("Fastest")
        btn_fast.clicked.connect(self._select_fastest)
        btn_row.addWidget(btn_fast)

        btn_secure = QPushButton("Most Secure")
        btn_secure.clicked.connect(self._select_most_secure)
        btn_row.addWidget(btn_secure)

        btn_none = QPushButton("Clear All")
        btn_none.clicked.connect(self._clear_all)
        btn_row.addWidget(btn_none)

        layout.addLayout(btn_row)

        # ── Cipher checklist ─────────────────────────────────────
        self.lst_ciphers = QListWidget()
        self.lst_ciphers.setMaximumHeight(180)
        self.lst_ciphers.setSelectionMode(
            QAbstractItemView.SelectionMode.NoSelection
        )

        all_info = CipherFactory.get_all_info()
        for info in all_info:
            item = QListWidgetItem()
            cb = QCheckBox(
                f"{info['name']:25s}  │  "
                f"{info['key_bits']:>3d}-bit  │  "
                f"{info['category']:<12s}  │  "
                f"{info['security']}"
            )
            cb.setChecked(True)
            cb.setProperty("cipher_name", info["name"])
            cb.stateChanged.connect(lambda _: self.cipher_changed.emit())
            self.lst_ciphers.addItem(item)
            self.lst_ciphers.setItemWidget(item, cb)

        layout.addWidget(self.lst_ciphers)

        self._on_preferred_changed(self.cmb_preferred.currentText())

    # ── Getters ──────────────────────────────────────────────────

    def get_preferred_cipher(self) -> str:
        """Return the single preferred cipher."""
        return self.cmb_preferred.currentText()

    def get_allowed_ciphers(self) -> list[str]:
        """Return all checked cipher names in preference order."""
        result = []
        preferred = self.cmb_preferred.currentText()

        # Put preferred first
        if preferred and self._is_checked(preferred):
            result.append(preferred)

        # Then add the rest in order
        for i in range(self.lst_ciphers.count()):
            item = self.lst_ciphers.item(i)
            cb = self.lst_ciphers.itemWidget(item)
            if isinstance(cb, QCheckBox) and cb.isChecked():
                name = cb.property("cipher_name")
                if name and name not in result:
                    result.append(name)

        return result if result else ["AES-256-GCM"]

    def get_ordered_preference(self) -> list[str]:
        """Return checked ciphers with preferred first."""
        return self.get_allowed_ciphers()

    def set_preferred(self, cipher_name: str):
        """Programmatically set the preferred cipher."""
        idx = self.cmb_preferred.findText(cipher_name)
        if idx >= 0:
            self.cmb_preferred.setCurrentIndex(idx)

    # ── Quick selections ─────────────────────────────────────────

    def _select_all(self):
        self._set_all_checked(True)

    def _clear_all(self):
        self._set_all_checked(False)

    def _select_aead_only(self):
        aead_ciphers = CipherFactory.list_aead_ciphers()
        for i in range(self.lst_ciphers.count()):
            cb = self.lst_ciphers.itemWidget(self.lst_ciphers.item(i))
            if isinstance(cb, QCheckBox):
                name = cb.property("cipher_name")
                cb.setChecked(name in aead_ciphers)

    def _select_fastest(self):
        fast = {"AES-128-GCM", "AES-192-GCM", "CHACHA20-POLY1305"}
        for i in range(self.lst_ciphers.count()):
            cb = self.lst_ciphers.itemWidget(self.lst_ciphers.item(i))
            if isinstance(cb, QCheckBox):
                cb.setChecked(cb.property("cipher_name") in fast)
        self.cmb_preferred.setCurrentText("AES-128-GCM")

    def _select_most_secure(self):
        secure = {"AES-256-GCM", "CHACHA20-POLY1305", "AES-256-CBC",
                  "AES-256-CTR", "CAMELLIA-256-CBC"}
        for i in range(self.lst_ciphers.count()):
            cb = self.lst_ciphers.itemWidget(self.lst_ciphers.item(i))
            if isinstance(cb, QCheckBox):
                cb.setChecked(cb.property("cipher_name") in secure)
        self.cmb_preferred.setCurrentText("AES-256-GCM")

    # ── Helpers ──────────────────────────────────────────────────

    def _set_all_checked(self, state: bool):
        for i in range(self.lst_ciphers.count()):
            cb = self.lst_ciphers.itemWidget(self.lst_ciphers.item(i))
            if isinstance(cb, QCheckBox):
                cb.setChecked(state)
        self.cipher_changed.emit()

    def _is_checked(self, cipher_name: str) -> bool:
        for i in range(self.lst_ciphers.count()):
            cb = self.lst_ciphers.itemWidget(self.lst_ciphers.item(i))
            if (
                isinstance(cb, QCheckBox)
                and cb.property("cipher_name") == cipher_name
            ):
                return cb.isChecked()
        return False

    def _on_preferred_changed(self, name: str):
        if not name:
            return
        try:
            info = CipherFactory.get_info(name)
            self.lbl_info.setText(
                f"🔑 {info['key_bits']}-bit  •  "
                f"{'🛡️ AEAD' if info['aead'] else '🔗 HMAC'}  •  "
                f"⚡ {info['speed']}"
            )
        except ValueError:
            self.lbl_info.setText("")
        self.cipher_changed.emit()

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
        self.tab_e2e           = E2EMessagingTab(self.bridge)     # NEW
        self.tab_logs          = LogsTab(self.log_handler)

        self.tabs.addTab(self.tab_dashboard,     "📊 Dashboard")
        self.tabs.addTab(self.tab_tunnel_server, "🖥️ Tunnel Server")
        self.tabs.addTab(self.tab_tunnel_client, "🔗 Tunnel Client")
        self.tabs.addTab(self.tab_proxy,         "🌐 Proxy")
        self.tabs.addTab(self.tab_e2e,           "💬 E2E Messaging")  # NEW
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
        # Determine active cipher
        cipher = (
            self.tab_tunnel_client.active_cipher
            or self.tab_proxy.active_cipher
            or "—"
        )

        # Get cipher details
        cipher_details = None
        if cipher != "—":
            try:
                cipher_details = CipherFactory.get_info(cipher)
            except ValueError:
                pass

        self.tab_dashboard.update_status(
            tunnel_running=self.tab_tunnel_server.is_running,
            proxy_running=self.tab_proxy.is_running,
            session_count=self.tab_tunnel_server.session_manager.active_count(),
            key_count=self.tab_keys.key_count,
            start_time=self.start_time,
            active_cipher=cipher,
            cipher_details=cipher_details,
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

        if self.tab_e2e.peer_client:
            self.tab_e2e._disconnect()

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