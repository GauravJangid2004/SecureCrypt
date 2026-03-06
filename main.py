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

# import sys
# import os
# import time
# import logging
# import threading
# from datetime import datetime
# from PyQt6.QtWidgets import (
#     QApplication, QMainWindow, QWidget, QTabWidget,
#     QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
#     QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox,
#     QGroupBox, QSpinBox, QFileDialog, QMessageBox,
#     QTableWidget, QTableWidgetItem, QHeaderView,
#     QSplitter, QStatusBar, QCheckBox, QPlainTextEdit,
#     QSizePolicy,
# )
# from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
# from PyQt6.QtGui import QFont, QColor, QIcon, QTextCursor

# # ── SecureCrypt imports ──────────────────────────────────────────
# from config.settings import Settings

# from core.crypto_engine import AESCrypto, RSACrypto, ECCCrypto, HashCrypto
# from core.crypto_engine import CipherFactory

# from utils.random_gen     import SecureRandom
# from utils.key_manager    import KeyManager
# from utils.secure_storage import SecureStorage
# from utils.framing        import Framing, MessageType

# from traffic.handshake       import HandshakeProtocol
# from traffic.session_manager import Session, SessionManager
# from traffic.tunnel_server   import TunnelServer, TunnelClient
# from traffic.proxy_client    import ProxyServer, SystemProxyConfig, PACFileGenerator

# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Qt Log Handler — routes Python logging into the GUI
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# class QtLogSignal(QObject):
#     """Bridge: Python logging → Qt signal."""
#     log_message = pyqtSignal(str)


# class QtLogHandler(logging.Handler):
#     """Logging handler that emits a Qt signal for each record."""

#     def __init__(self):
#         super().__init__()
#         self.signal_emitter = QtLogSignal()
#         fmt = logging.Formatter(
#             "[%(asctime)s] [%(levelname)-8s] %(name)-28s — %(message)s",
#             datefmt="%H:%M:%S",
#         )
#         self.setFormatter(fmt)

#     def emit(self, record):
#         msg = self.format(record)
#         self.signal_emitter.log_message.emit(msg)


# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Signal Bridge — thread-safe callbacks → GUI updates
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# class SignalBridge(QObject):
#     session_created = pyqtSignal(dict)       # session.info()
#     session_closed  = pyqtSignal(str)        # session_id
#     data_received   = pyqtSignal(str, int)   # session_id, byte count
#     proxy_request   = pyqtSignal(str, str, int)  # method, host, port
#     status_update   = pyqtSignal(str)        # status bar message


# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Style Constants
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# STYLE_SHEET = """
# QMainWindow {
#     background-color: #1e1e2e;
# }
# QTabWidget::pane {
#     border: 1px solid #313244;
#     background-color: #1e1e2e;
# }
# QTabBar::tab {
#     background-color: #313244;
#     color: #cdd6f4;
#     padding: 8px 20px;
#     margin-right: 2px;
#     border-top-left-radius: 6px;
#     border-top-right-radius: 6px;
# }
# QTabBar::tab:selected {
#     background-color: #45475a;
#     color: #89b4fa;
#     font-weight: bold;
# }
# QGroupBox {
#     color: #89b4fa;
#     border: 1px solid #45475a;
#     border-radius: 8px;
#     margin-top: 12px;
#     padding-top: 16px;
#     font-weight: bold;
# }
# QGroupBox::title {
#     subcontrol-origin: margin;
#     left: 12px;
#     padding: 0 6px;
# }
# QPushButton {
#     background-color: #89b4fa;
#     color: #1e1e2e;
#     border: none;
#     padding: 8px 18px;
#     border-radius: 6px;
#     font-weight: bold;
# }
# QPushButton:hover {
#     background-color: #74c7ec;
# }
# QPushButton:pressed {
#     background-color: #585b70;
# }
# QPushButton:disabled {
#     background-color: #45475a;
#     color: #6c7086;
# }
# QPushButton[danger="true"] {
#     background-color: #f38ba8;
# }
# QPushButton[danger="true"]:hover {
#     background-color: #eba0ac;
# }
# QPushButton[success="true"] {
#     background-color: #a6e3a1;
# }
# QLineEdit, QSpinBox, QComboBox {
#     background-color: #313244;
#     color: #cdd6f4;
#     border: 1px solid #45475a;
#     border-radius: 5px;
#     padding: 6px;
# }
# QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
#     border: 1px solid #89b4fa;
# }
# QTextEdit, QPlainTextEdit {
#     background-color: #11111b;
#     color: #a6e3a1;
#     border: 1px solid #313244;
#     border-radius: 5px;
#     font-family: 'Consolas', 'Courier New', monospace;
#     font-size: 12px;
# }
# QTableWidget {
#     background-color: #1e1e2e;
#     color: #cdd6f4;
#     gridline-color: #313244;
#     border: 1px solid #45475a;
#     border-radius: 5px;
# }
# QTableWidget::item {
#     padding: 4px;
# }
# QTableWidget::item:selected {
#     background-color: #45475a;
# }
# QHeaderView::section {
#     background-color: #313244;
#     color: #89b4fa;
#     padding: 6px;
#     border: 1px solid #45475a;
#     font-weight: bold;
# }
# QLabel {
#     color: #cdd6f4;
# }
# QStatusBar {
#     background-color: #181825;
#     color: #a6adc8;
# }
# QCheckBox {
#     color: #cdd6f4;
# }
# QCheckBox::indicator:checked {
#     background-color: #89b4fa;
#     border-radius: 3px;
# }
# """

# MONO_FONT = QFont("Consolas", 10)


# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Tab 1 — Dashboard
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# class DashboardTab(QWidget):
#     def __init__(self, bridge: SignalBridge, parent=None):
#         super().__init__(parent)
#         self.bridge = bridge
#         self._build_ui()

#         # refresh every 2 seconds
#         self._timer = QTimer(self)
#         self._timer.timeout.connect(self.refresh)
#         self._timer.start(2000)

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         # ── header ───────────────────────────────────────────────
#         header = QLabel(f"🔐  {Settings.APP_NAME}  v{Settings.APP_VERSION}")
#         header.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
#         header.setAlignment(Qt.AlignmentFlag.AlignCenter)
#         header.setStyleSheet("color: #89b4fa; padding: 16px;")
#         layout.addWidget(header)

#         subtitle = QLabel(
#             "End-to-end encrypted traffic protection"
#         )
#         subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
#         subtitle.setStyleSheet("color: #6c7086; font-size: 13px;")
#         layout.addWidget(subtitle)

#         # ── status cards ─────────────────────────────────────────
#         cards_layout = QHBoxLayout()

#         self.card_tunnel = self._make_card("Tunnel Server", "⏹ Stopped")
#         self.card_proxy  = self._make_card("Proxy Server",  "⏹ Stopped")
#         self.card_sessions = self._make_card("Active Sessions", "0")
#         self.card_keys   = self._make_card("Keys on Disk", "—")

#         cards_layout.addWidget(self.card_tunnel)
#         cards_layout.addWidget(self.card_proxy)
#         cards_layout.addWidget(self.card_sessions)
#         cards_layout.addWidget(self.card_keys)
#         layout.addLayout(cards_layout)

#         # ── info group ───────────────────────────────────────────
#         info_group = QGroupBox("System Information")
#         info_layout = QFormLayout(info_group)

#         self.lbl_tunnel_addr = QLabel("—")
#         self.lbl_proxy_addr  = QLabel("—")
#         self.lbl_cipher      = QLabel(Settings.DEFAULT_CIPHER)
#         self.lbl_uptime      = QLabel("—")

#         info_layout.addRow("Tunnel Address:", self.lbl_tunnel_addr)
#         info_layout.addRow("Proxy Address:",  self.lbl_proxy_addr)
#         info_layout.addRow("Default Cipher:", self.lbl_cipher)
#         info_layout.addRow("Uptime:",         self.lbl_uptime)
#         layout.addWidget(info_group)

#         layout.addStretch()

#     def _make_card(self, title: str, value: str) -> QGroupBox:
#         card = QGroupBox(title)
#         card.setFixedHeight(100)
#         vl = QVBoxLayout(card)
#         lbl = QLabel(value)
#         lbl.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
#         lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
#         lbl.setObjectName("card_value")
#         vl.addWidget(lbl)
#         return card

#     def _card_value(self, card: QGroupBox) -> QLabel:
#         return card.findChild(QLabel, "card_value")

#     def refresh(self):
#         """Called by parent window with live state."""
#         pass  # filled in by MainWindow

#     def update_status(
#         self,
#         tunnel_running: bool,
#         proxy_running: bool,
#         session_count: int,
#         key_count: int,
#         start_time: float,
#     ):
#         self._card_value(self.card_tunnel).setText(
#             "✅ Running" if tunnel_running else "⏹ Stopped"
#         )
#         self._card_value(self.card_proxy).setText(
#             "✅ Running" if proxy_running else "⏹ Stopped"
#         )
#         self._card_value(self.card_sessions).setText(str(session_count))
#         self._card_value(self.card_keys).setText(str(key_count))

#         if tunnel_running:
#             self.lbl_tunnel_addr.setText(
#                 f"{Settings.TUNNEL_HOST}:{Settings.TUNNEL_PORT}"
#             )
#         else:
#             self.lbl_tunnel_addr.setText("—")

#         if proxy_running:
#             self.lbl_proxy_addr.setText(
#                 f"{Settings.PROXY_HOST}:{Settings.PROXY_PORT}"
#             )
#         else:
#             self.lbl_proxy_addr.setText("—")

#         elapsed = int(time.time() - start_time)
#         h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
#         self.lbl_uptime.setText(f"{h:02d}:{m:02d}:{s:02d}")


# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Tab 2 — Tunnel Server
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# class TunnelServerTab(QWidget):
#     def __init__(self, bridge: SignalBridge, parent=None):
#         super().__init__(parent)
#         self.bridge = bridge
#         self.tunnel_server: TunnelServer | None = None
#         self.session_manager = SessionManager(
#             timeout=Settings.SESSION_TIMEOUT
#         )
#         self._build_ui()

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         # ── config ───────────────────────────────────────────────
#         config_group = QGroupBox("Server Configuration")
#         config_layout = QGridLayout(config_group)

#         config_layout.addWidget(QLabel("Bind Host:"), 0, 0)
#         self.txt_host = QLineEdit(Settings.TUNNEL_HOST)
#         config_layout.addWidget(self.txt_host, 0, 1)

#         config_layout.addWidget(QLabel("Bind Port:"), 0, 2)
#         self.spn_port = QSpinBox()
#         self.spn_port.setRange(1, 65535)
#         self.spn_port.setValue(Settings.TUNNEL_PORT)
#         config_layout.addWidget(self.spn_port, 0, 3)

#         config_layout.addWidget(QLabel("Server ID:"), 1, 0)
#         self.txt_server_id = QLineEdit("securecrypt-server")
#         config_layout.addWidget(self.txt_server_id, 1, 1)

#         config_layout.addWidget(QLabel("Forward Host:"), 1, 2)
#         self.txt_fwd_host = QLineEdit("")
#         self.txt_fwd_host.setPlaceholderText("Optional (e.g. 127.0.0.1)")
#         config_layout.addWidget(self.txt_fwd_host, 1, 3)

#         config_layout.addWidget(QLabel("Forward Port:"), 2, 0)
#         self.spn_fwd_port = QSpinBox()
#         self.spn_fwd_port.setRange(0, 65535)
#         self.spn_fwd_port.setValue(0)
#         config_layout.addWidget(self.spn_fwd_port, 2, 1)

#         layout.addWidget(config_group)

#         # ── controls ─────────────────────────────────────────────
#         btn_layout = QHBoxLayout()
#         self.btn_start = QPushButton("▶  Start Server")
#         self.btn_start.clicked.connect(self.start_server)
#         btn_layout.addWidget(self.btn_start)

#         self.btn_stop = QPushButton("⏹  Stop Server")
#         self.btn_stop.setProperty("danger", True)
#         self.btn_stop.setEnabled(False)
#         self.btn_stop.clicked.connect(self.stop_server)
#         btn_layout.addWidget(self.btn_stop)

#         self.btn_refresh = QPushButton("🔄  Refresh Sessions")
#         self.btn_refresh.clicked.connect(self.refresh_sessions)
#         btn_layout.addWidget(self.btn_refresh)

#         layout.addLayout(btn_layout)

#         # ── session table ────────────────────────────────────────
#         sessions_group = QGroupBox("Active Sessions")
#         sessions_layout = QVBoxLayout(sessions_group)

#         self.tbl_sessions = QTableWidget(0, 7)
#         self.tbl_sessions.setHorizontalHeaderLabels([
#             "Session ID", "Peer", "Cipher", "Created",
#             "Last Activity", "Sent", "Received",
#         ])
#         self.tbl_sessions.horizontalHeader().setSectionResizeMode(
#             QHeaderView.ResizeMode.Stretch
#         )
#         self.tbl_sessions.setEditTriggers(
#             QTableWidget.EditTrigger.NoEditTriggers
#         )
#         sessions_layout.addWidget(self.tbl_sessions)
#         layout.addWidget(sessions_group)

#         # connect signals
#         self.bridge.session_created.connect(self._on_session_created)
#         self.bridge.session_closed.connect(self._on_session_closed)

#     def start_server(self):
#         try:
#             fwd_host = self.txt_fwd_host.text().strip() or None
#             fwd_port = self.spn_fwd_port.value() or None

#             self.tunnel_server = TunnelServer(
#                 host=self.txt_host.text().strip(),
#                 port=self.spn_port.value(),
#                 forward_host=fwd_host,
#                 forward_port=fwd_port,
#                 session_manager=self.session_manager,
#                 server_id=self.txt_server_id.text().strip(),
#                 on_session_created=self._cb_session_created,
#                 on_session_closed=self._cb_session_closed,
#                 on_data_received=self._cb_data_received,
#             )
#             self.tunnel_server.start()

#             self.btn_start.setEnabled(False)
#             self.btn_stop.setEnabled(True)
#             self.txt_host.setEnabled(False)
#             self.spn_port.setEnabled(False)
#             self.bridge.status_update.emit("Tunnel server started")

#         except Exception as exc:
#             QMessageBox.critical(self, "Error", str(exc))

#     def stop_server(self):
#         if self.tunnel_server:
#             self.tunnel_server.stop()
#             self.tunnel_server = None
#         self.btn_start.setEnabled(True)
#         self.btn_stop.setEnabled(False)
#         self.txt_host.setEnabled(True)
#         self.spn_port.setEnabled(True)
#         self.tbl_sessions.setRowCount(0)
#         self.bridge.status_update.emit("Tunnel server stopped")

#     def refresh_sessions(self):
#         infos = self.session_manager.all_info()
#         self.tbl_sessions.setRowCount(len(infos))
#         for row, info in enumerate(infos):
#             self.tbl_sessions.setItem(
#                 row, 0, QTableWidgetItem(info["session_id"][:16] + "…")
#             )
#             self.tbl_sessions.setItem(
#                 row, 1, QTableWidgetItem(info["peer"])
#             )
#             self.tbl_sessions.setItem(
#                 row, 2, QTableWidgetItem(info["cipher"])
#             )
#             self.tbl_sessions.setItem(
#                 row, 3, QTableWidgetItem(
#                     datetime.fromtimestamp(
#                         info["created"]
#                     ).strftime("%H:%M:%S")
#                 )
#             )
#             self.tbl_sessions.setItem(
#                 row, 4, QTableWidgetItem(
#                     datetime.fromtimestamp(
#                         info["last_activity"]
#                     ).strftime("%H:%M:%S")
#                 )
#             )
#             self.tbl_sessions.setItem(
#                 row, 5, QTableWidgetItem(
#                     self._fmt_bytes(info["bytes_sent"])
#                 )
#             )
#             self.tbl_sessions.setItem(
#                 row, 6, QTableWidgetItem(
#                     self._fmt_bytes(info["bytes_received"])
#                 )
#             )

#     @staticmethod
#     def _fmt_bytes(n: int) -> str:
#         for unit in ("B", "KB", "MB", "GB"):
#             if n < 1024:
#                 return f"{n:.1f} {unit}"
#             n /= 1024
#         return f"{n:.1f} TB"

#     # ── thread-safe callbacks ────────────────────────────────────
#     def _cb_session_created(self, session: Session):
#         self.bridge.session_created.emit(session.info())

#     def _cb_session_closed(self, sid: str):
#         self.bridge.session_closed.emit(sid)

#     def _cb_data_received(self, sid: str, data: bytes):
#         self.bridge.data_received.emit(sid, len(data))

#     def _on_session_created(self, info: dict):
#         self.refresh_sessions()

#     def _on_session_closed(self, sid: str):
#         self.refresh_sessions()

#     @property
#     def is_running(self) -> bool:
#         return self.tunnel_server is not None and self.tunnel_server.is_running


# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Tab 3 — Tunnel Client
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# class TunnelClientTab(QWidget):
#     def __init__(self, bridge: SignalBridge, parent=None):
#         super().__init__(parent)
#         self.bridge = bridge
#         self.tunnel_client: TunnelClient | None = None
#         self._build_ui()

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         # ── connection settings ──────────────────────────────────
#         conn_group = QGroupBox("Remote Tunnel Server")
#         conn_layout = QGridLayout(conn_group)

#         conn_layout.addWidget(QLabel("Remote Host:"), 0, 0)
#         self.txt_remote_host = QLineEdit("127.0.0.1")
#         conn_layout.addWidget(self.txt_remote_host, 0, 1)

#         conn_layout.addWidget(QLabel("Remote Port:"), 0, 2)
#         self.spn_remote_port = QSpinBox()
#         self.spn_remote_port.setRange(1, 65535)
#         self.spn_remote_port.setValue(Settings.TUNNEL_PORT)
#         conn_layout.addWidget(self.spn_remote_port, 0, 3)

#         conn_layout.addWidget(QLabel("Local Listen Host:"), 1, 0)
#         self.txt_local_host = QLineEdit("127.0.0.1")
#         self.txt_local_host.setPlaceholderText("Optional")
#         conn_layout.addWidget(self.txt_local_host, 1, 1)

#         conn_layout.addWidget(QLabel("Local Listen Port:"), 1, 2)
#         self.spn_local_port = QSpinBox()
#         self.spn_local_port.setRange(0, 65535)
#         self.spn_local_port.setValue(0)
#         conn_layout.addWidget(self.spn_local_port, 1, 3)

#         layout.addWidget(conn_group)

#         # ── buttons ──────────────────────────────────────────────
#         btn_layout = QHBoxLayout()

#         self.btn_connect = QPushButton("🔗  Connect")
#         self.btn_connect.clicked.connect(self.connect_tunnel)
#         btn_layout.addWidget(self.btn_connect)

#         self.btn_disconnect = QPushButton("❌  Disconnect")
#         self.btn_disconnect.setProperty("danger", True)
#         self.btn_disconnect.setEnabled(False)
#         self.btn_disconnect.clicked.connect(self.disconnect_tunnel)
#         btn_layout.addWidget(self.btn_disconnect)

#         layout.addLayout(btn_layout)

#         # ── session info ─────────────────────────────────────────
#         info_group = QGroupBox("Session Info")
#         info_layout = QFormLayout(info_group)

#         self.lbl_status   = QLabel("Disconnected")
#         self.lbl_sess_id  = QLabel("—")
#         self.lbl_cipher   = QLabel("—")
#         self.lbl_sent     = QLabel("0 B")
#         self.lbl_recv     = QLabel("0 B")

#         info_layout.addRow("Status:",     self.lbl_status)
#         info_layout.addRow("Session ID:", self.lbl_sess_id)
#         info_layout.addRow("Cipher:",     self.lbl_cipher)
#         info_layout.addRow("Sent:",       self.lbl_sent)
#         info_layout.addRow("Received:",   self.lbl_recv)
#         layout.addWidget(info_group)

#         # ── send test data ───────────────────────────────────────
#         test_group = QGroupBox("Send Test Data")
#         test_layout = QHBoxLayout(test_group)

#         self.txt_test_msg = QLineEdit()
#         self.txt_test_msg.setPlaceholderText(
#             "Type a message to send through the encrypted tunnel…"
#         )
#         test_layout.addWidget(self.txt_test_msg)

#         self.btn_send = QPushButton("📤 Send")
#         self.btn_send.setEnabled(False)
#         self.btn_send.clicked.connect(self.send_test)
#         test_layout.addWidget(self.btn_send)
#         layout.addWidget(test_group)

#         layout.addStretch()

#         # refresh timer
#         self._timer = QTimer(self)
#         self._timer.timeout.connect(self._refresh_info)
#         self._timer.start(1000)

#     def connect_tunnel(self):
#         def _do_connect():
#             try:
#                 local_host = self.txt_local_host.text().strip() or None
#                 local_port = self.spn_local_port.value() or None

#                 self.tunnel_client = TunnelClient(
#                     remote_host=self.txt_remote_host.text().strip(),
#                     remote_port=self.spn_remote_port.value(),
#                     local_listen_host=local_host,
#                     local_listen_port=local_port,
#                     on_session_created=lambda s: (
#                         self.bridge.session_created.emit(s.info())
#                     ),
#                     on_session_closed=lambda sid: (
#                         self.bridge.session_closed.emit(sid)
#                     ),
#                 )
#                 self.tunnel_client.connect()

#                 if local_host and local_port:
#                     self.tunnel_client.start_local_listener()
#                 self.tunnel_client.start_keepalive()

#                 self.bridge.status_update.emit(
#                     "Connected to tunnel server"
#                 )
#             except Exception as exc:
#                 self.bridge.status_update.emit(f"Connect failed: {exc}")

#         self.btn_connect.setEnabled(False)
#         threading.Thread(target=_do_connect, daemon=True).start()

#     def disconnect_tunnel(self):
#         if self.tunnel_client:
#             self.tunnel_client.disconnect()
#             self.tunnel_client = None
#         self.btn_connect.setEnabled(True)
#         self.btn_disconnect.setEnabled(False)
#         self.btn_send.setEnabled(False)
#         self.lbl_status.setText("Disconnected")
#         self.lbl_sess_id.setText("—")
#         self.lbl_cipher.setText("—")
#         self.bridge.status_update.emit("Disconnected from tunnel")

#     def send_test(self):
#         msg = self.txt_test_msg.text().strip()
#         if not msg or not self.tunnel_client:
#             return
#         try:
#             self.tunnel_client.send(msg.encode("utf-8"))
#             self.txt_test_msg.clear()
#             self.bridge.status_update.emit(
#                 f"Sent {len(msg)} bytes"
#             )
#         except Exception as exc:
#             QMessageBox.warning(self, "Send Error", str(exc))

#     def _refresh_info(self):
#         if (
#             self.tunnel_client
#             and self.tunnel_client.is_connected
#         ):
#             self.btn_connect.setEnabled(False)
#             self.btn_disconnect.setEnabled(True)
#             self.btn_send.setEnabled(True)
#             self.lbl_status.setText("🟢 Connected")
#             info = self.tunnel_client.session_info
#             if info:
#                 self.lbl_sess_id.setText(info["session_id"][:16] + "…")
#                 self.lbl_cipher.setText(info["cipher"])
#                 self.lbl_sent.setText(
#                     TunnelServerTab._fmt_bytes(info["bytes_sent"])
#                 )
#                 self.lbl_recv.setText(
#                     TunnelServerTab._fmt_bytes(info["bytes_received"])
#                 )
#         else:
#             if not self.btn_connect.isEnabled():
#                 self.btn_connect.setEnabled(True)
#                 self.btn_disconnect.setEnabled(False)
#                 self.btn_send.setEnabled(False)


# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Tab 4 — Proxy Server
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# class ProxyTab(QWidget):
#     def __init__(self, bridge: SignalBridge, parent=None):
#         super().__init__(parent)
#         self.bridge = bridge
#         self.proxy_server: ProxyServer | None = None
#         self.logger = logging.getLogger("SecureCrypt.ProxyTab")
#         self._build_ui()

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         # ── config ───────────────────────────────────────────────
#         config_group = QGroupBox("Proxy Configuration")
#         config_layout = QGridLayout(config_group)

#         config_layout.addWidget(QLabel("Listen Host:"), 0, 0)
#         self.txt_host = QLineEdit(Settings.PROXY_HOST)
#         config_layout.addWidget(self.txt_host, 0, 1)

#         config_layout.addWidget(QLabel("Listen Port:"), 0, 2)
#         self.spn_port = QSpinBox()
#         self.spn_port.setRange(1, 65535)
#         self.spn_port.setValue(Settings.PROXY_PORT)
#         config_layout.addWidget(self.spn_port, 0, 3)

#         layout.addWidget(config_group)

#         # ── buttons ──────────────────────────────────────────────
#         btn_layout = QHBoxLayout()

#         self.btn_start = QPushButton("▶  Start Proxy")
#         self.btn_start.clicked.connect(self.start_proxy)
#         btn_layout.addWidget(self.btn_start)

#         self.btn_stop = QPushButton("⏹  Stop Proxy")
#         self.btn_stop.setProperty("danger", True)
#         self.btn_stop.setEnabled(False)
#         self.btn_stop.clicked.connect(self.stop_proxy)
#         btn_layout.addWidget(self.btn_stop)

#         self.btn_sys_proxy = QPushButton("🖥️  Set System Proxy")
#         self.btn_sys_proxy.clicked.connect(self._set_system_proxy)
#         btn_layout.addWidget(self.btn_sys_proxy)

#         self.btn_unset_proxy = QPushButton("↩️  Unset System Proxy")
#         self.btn_unset_proxy.setProperty("danger", True)
#         self.btn_unset_proxy.clicked.connect(self._unset_system_proxy)
#         btn_layout.addWidget(self.btn_unset_proxy)

#         layout.addLayout(btn_layout)

#         # ── info panel ───────────────────────────────────────────
#         info_group = QGroupBox("Proxy Status")
#         info_fl = QFormLayout(info_group)

#         self.lbl_status     = QLabel("⏹ Stopped")
#         self.lbl_mode       = QLabel("—")
#         self.lbl_requests   = QLabel("0")
#         self.lbl_active     = QLabel("0")
#         self.lbl_blocked    = QLabel("0")
#         self.lbl_tunnel     = QLabel("❌ No tunnel")
#         self.lbl_pac        = QLabel("—")

#         info_fl.addRow("Status:",             self.lbl_status)
#         info_fl.addRow("Mode:",               self.lbl_mode)
#         info_fl.addRow("Total Requests:",     self.lbl_requests)
#         info_fl.addRow("Active Connections:", self.lbl_active)
#         info_fl.addRow("Blocked:",           self.lbl_blocked)
#         info_fl.addRow("Tunnel Encryption:", self.lbl_tunnel)
#         info_fl.addRow("PAC File URL:",      self.lbl_pac)

#         layout.addWidget(info_group)

#         # ── domain blocking ──────────────────────────────────────
#         block_group = QGroupBox("Domain Blocking")
#         block_layout = QHBoxLayout(block_group)

#         self.txt_block_domain = QLineEdit()
#         self.txt_block_domain.setPlaceholderText(
#             "e.g. ads.example.com"
#         )
#         block_layout.addWidget(self.txt_block_domain)

#         self.btn_block = QPushButton("🚫 Block")
#         self.btn_block.clicked.connect(self._block_domain)
#         block_layout.addWidget(self.btn_block)

#         self.btn_unblock = QPushButton("✅ Unblock")
#         self.btn_unblock.clicked.connect(self._unblock_domain)
#         block_layout.addWidget(self.btn_unblock)

#         layout.addWidget(block_group)

#         # ── request log ──────────────────────────────────────────
#         log_group = QGroupBox("Live Request Log")
#         log_layout = QVBoxLayout(log_group)

#         self.txt_log = QPlainTextEdit()
#         self.txt_log.setReadOnly(True)
#         self.txt_log.setMaximumBlockCount(500)
#         log_layout.addWidget(self.txt_log)

#         layout.addWidget(log_group)

#         # ── browser setup instructions ───────────────────────────
#         hint_group = QGroupBox("📋 Browser Setup Instructions")
#         hint_layout = QVBoxLayout(hint_group)

#         self.txt_instructions = QPlainTextEdit()
#         self.txt_instructions.setReadOnly(True)
#         self.txt_instructions.setMaximumHeight(150)
#         self.txt_instructions.setPlainText(
#             SystemProxyConfig.get_manual_instructions(
#                 Settings.PROXY_HOST, Settings.PROXY_PORT
#             )
#         )
#         hint_layout.addWidget(self.txt_instructions)
#         layout.addWidget(hint_group)

#         # ── signals ──────────────────────────────────────────────
#         self.bridge.proxy_request.connect(self._on_proxy_request)

#         # ── refresh timer ────────────────────────────────────────
#         self._timer = QTimer(self)
#         self._timer.timeout.connect(self._refresh_stats)
#         self._timer.start(1000)

#     # ── actions ──────────────────────────────────────────────────

#     def start_proxy(self):
#         try:
#             host = self.txt_host.text().strip()
#             port = self.spn_port.value()

#             self.proxy_server = ProxyServer(
#                 host=host,
#                 port=port,
#                 on_request=self._cb_request,
#             )
#             self.proxy_server.start()

#             self.btn_start.setEnabled(False)
#             self.btn_stop.setEnabled(True)
#             self.txt_host.setEnabled(False)
#             self.spn_port.setEnabled(False)
#             self.lbl_status.setText("✅ Running")
#             self.lbl_pac.setText(f"http://{host}:{port}/proxy.pac")

#             self.txt_instructions.setPlainText(
#                 SystemProxyConfig.get_manual_instructions(host, port)
#             )

#             self.bridge.status_update.emit(
#                 f"Proxy started on {host}:{port}"
#             )
#         except Exception as exc:
#             QMessageBox.critical(self, "Error", str(exc))

#     def stop_proxy(self):
#         if self.proxy_server:
#             self.proxy_server.stop()
#             self.proxy_server = None
#         self.btn_start.setEnabled(True)
#         self.btn_stop.setEnabled(False)
#         self.txt_host.setEnabled(True)
#         self.spn_port.setEnabled(True)
#         self.lbl_status.setText("⏹ Stopped")
#         self.lbl_pac.setText("—")
#         self.bridge.status_update.emit("Proxy stopped")

#     def attach_tunnel_session(self, session: Session | None):
#         """Connect proxy to encrypted tunnel."""
#         if self.proxy_server:
#             self.proxy_server.tunnel_session = session
#             mode = "ENCRYPTED" if session else "DIRECT"
#             self.logger.info("Proxy mode changed to %s", mode)

#     def _set_system_proxy(self):
#         host = self.txt_host.text().strip()
#         port = self.spn_port.value()
#         success, msg = SystemProxyConfig.enable_system_proxy(
#             host, port
#         )
#         if success:
#             QMessageBox.information(self, "Success", msg)
#         else:
#             QMessageBox.warning(self, "Failed", msg)
#         self.bridge.status_update.emit(msg)

#     def _unset_system_proxy(self):
#         success, msg = SystemProxyConfig.disable_system_proxy()
#         if success:
#             QMessageBox.information(self, "Success", msg)
#         else:
#             QMessageBox.warning(self, "Failed", msg)
#         self.bridge.status_update.emit(msg)

#     def _block_domain(self):
#         domain = self.txt_block_domain.text().strip()
#         if domain and self.proxy_server:
#             self.proxy_server.add_blocked_domain(domain)
#             self.txt_block_domain.clear()
#             self.bridge.status_update.emit(f"Blocked: {domain}")

#     def _unblock_domain(self):
#         domain = self.txt_block_domain.text().strip()
#         if domain and self.proxy_server:
#             self.proxy_server.remove_blocked_domain(domain)
#             self.txt_block_domain.clear()
#             self.bridge.status_update.emit(f"Unblocked: {domain}")

#     def _cb_request(self, method: str, host: str, port: int):
#         self.bridge.proxy_request.emit(method, host, port)

#     def _on_proxy_request(self, method: str, host: str, port: int):
#         from datetime import datetime
#         ts = datetime.now().strftime("%H:%M:%S")
#         encrypted = "🔒" if (
#             self.proxy_server
#             and self.proxy_server.tunnel_session
#             and self.proxy_server.tunnel_session.active
#         ) else "🔓"
#         self.txt_log.appendPlainText(
#             f"[{ts}] {encrypted} {method:8s} {host}:{port}"
#         )

#     def _refresh_stats(self):
#         if self.proxy_server and self.proxy_server.is_running:
#             stats = self.proxy_server.stats()
#             self.lbl_requests.setText(str(stats["total_requests"]))
#             self.lbl_active.setText(str(stats["active_connections"]))
#             self.lbl_blocked.setText(str(stats["blocked_requests"]))
#             self.lbl_mode.setText(stats["mode"])
#             self.lbl_tunnel.setText(
#                 "✅ Encrypted" if stats["tunnel_active"]
#                 else "🔓 Direct"
#             )

#     @property
#     def is_running(self) -> bool:
#         return (
#             self.proxy_server is not None
#             and self.proxy_server.is_running
#         )


# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Tab 5 — Crypto Tools
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# # class CryptoToolsTab(QWidget):
# #     def __init__(self, parent=None):
# #         super().__init__(parent)
# #         self._aes_key: bytes | None = None
# #         self._build_ui()

# #     def _build_ui(self):
# #         layout = QVBoxLayout(self)

# #         # ── AES section ──────────────────────────────────────────
# #         aes_group = QGroupBox("AES-256-GCM Encrypt / Decrypt")
# #         aes_layout = QVBoxLayout(aes_group)

# #         key_row = QHBoxLayout()
# #         key_row.addWidget(QLabel("AES Key (hex):"))
# #         self.txt_aes_key = QLineEdit()
# #         self.txt_aes_key.setPlaceholderText("Click Generate or paste 64 hex chars")
# #         key_row.addWidget(self.txt_aes_key)
# #         self.btn_gen_key = QPushButton("🔑 Generate")
# #         self.btn_gen_key.clicked.connect(self._gen_aes_key)
# #         key_row.addWidget(self.btn_gen_key)
# #         aes_layout.addLayout(key_row)

# #         self.txt_plain = QTextEdit()
# #         self.txt_plain.setPlaceholderText("Plaintext…")
# #         self.txt_plain.setMaximumHeight(100)
# #         aes_layout.addWidget(self.txt_plain)

# #         enc_dec_row = QHBoxLayout()
# #         self.btn_encrypt = QPushButton("🔒 Encrypt")
# #         self.btn_encrypt.clicked.connect(self._encrypt)
# #         enc_dec_row.addWidget(self.btn_encrypt)
# #         self.btn_decrypt = QPushButton("🔓 Decrypt")
# #         self.btn_decrypt.clicked.connect(self._decrypt)
# #         enc_dec_row.addWidget(self.btn_decrypt)
# #         aes_layout.addLayout(enc_dec_row)

# #         self.txt_cipher = QTextEdit()
# #         self.txt_cipher.setPlaceholderText("Ciphertext (hex)…")
# #         self.txt_cipher.setMaximumHeight(100)
# #         aes_layout.addWidget(self.txt_cipher)

# #         layout.addWidget(aes_group)

# #         # ── Hash section ─────────────────────────────────────────
# #         hash_group = QGroupBox("Hashing")
# #         hash_layout = QVBoxLayout(hash_group)

# #         hash_input_row = QHBoxLayout()
# #         self.txt_hash_input = QLineEdit()
# #         self.txt_hash_input.setPlaceholderText("Data to hash…")
# #         hash_input_row.addWidget(self.txt_hash_input)

# #         self.cmb_hash = QComboBox()
# #         self.cmb_hash.addItems(["SHA-256", "SHA-512", "BLAKE2b"])
# #         hash_input_row.addWidget(self.cmb_hash)

# #         self.btn_hash = QPushButton("#️⃣ Hash")
# #         self.btn_hash.clicked.connect(self._hash)
# #         hash_input_row.addWidget(self.btn_hash)
# #         hash_layout.addLayout(hash_input_row)

# #         self.txt_hash_output = QLineEdit()
# #         self.txt_hash_output.setReadOnly(True)
# #         self.txt_hash_output.setPlaceholderText("Hash output…")
# #         hash_layout.addWidget(self.txt_hash_output)

# #         layout.addWidget(hash_group)

# #         # ── RSA section ──────────────────────────────────────────
# #         rsa_group = QGroupBox("RSA Quick Test")
# #         rsa_layout = QVBoxLayout(rsa_group)

# #         self.btn_rsa_test = QPushButton(
# #             "🧪  Generate RSA-4096 → Encrypt → Decrypt round-trip"
# #         )
# #         self.btn_rsa_test.clicked.connect(self._rsa_test)
# #         rsa_layout.addWidget(self.btn_rsa_test)

# #         self.txt_rsa_result = QPlainTextEdit()
# #         self.txt_rsa_result.setReadOnly(True)
# #         self.txt_rsa_result.setMaximumHeight(120)
# #         rsa_layout.addWidget(self.txt_rsa_result)

# #         layout.addWidget(rsa_group)

# #         # ── ECC section ──────────────────────────────────────────
# #         ecc_group = QGroupBox("ECC Quick Test")
# #         ecc_layout = QVBoxLayout(ecc_group)

# #         self.btn_ecc_test = QPushButton(
# #             "🧪  ECDH Key Exchange + Sign/Verify round-trip"
# #         )
# #         self.btn_ecc_test.clicked.connect(self._ecc_test)
# #         ecc_layout.addWidget(self.btn_ecc_test)

# #         self.txt_ecc_result = QPlainTextEdit()
# #         self.txt_ecc_result.setReadOnly(True)
# #         self.txt_ecc_result.setMaximumHeight(120)
# #         ecc_layout.addWidget(self.txt_ecc_result)

# #         layout.addWidget(ecc_group)
# #         layout.addStretch()

# #     def _gen_aes_key(self):
# #         self._aes_key = SecureRandom.generate_bytes(32)
# #         self.txt_aes_key.setText(self._aes_key.hex())

# #     def _get_aes(self) -> AESCrypto | None:
# #         hex_key = self.txt_aes_key.text().strip()
# #         if not hex_key:
# #             QMessageBox.warning(
# #                 self, "No Key", "Generate or enter an AES key first."
# #             )
# #             return None
# #         try:
# #             key = bytes.fromhex(hex_key)
# #         except ValueError:
# #             QMessageBox.warning(self, "Bad Key", "Invalid hex key.")
# #             return None
# #         if len(key) not in (16, 24, 32):
# #             QMessageBox.warning(
# #                 self, "Bad Key", "Key must be 16, 24 or 32 bytes."
# #             )
# #             return None
# #         return AESCrypto(key=key)

# #     def _encrypt(self):
# #         aes = self._get_aes()
# #         if not aes:
# #             return
# #         pt = self.txt_plain.toPlainText().encode("utf-8")
# #         if not pt:
# #             return
# #         nonce, ct = aes.encrypt_gcm(pt)
# #         # store as nonce_hex:ct_hex
# #         self.txt_cipher.setPlainText(
# #             f"{nonce.hex()}:{ct.hex()}"
# #         )

# #     def _decrypt(self):
# #         aes = self._get_aes()
# #         if not aes:
# #             return
# #         raw = self.txt_cipher.toPlainText().strip()
# #         if ":" not in raw:
# #             QMessageBox.warning(
# #                 self, "Format", "Expected nonce_hex:ciphertext_hex"
# #             )
# #             return
# #         try:
# #             nonce_hex, ct_hex = raw.split(":", 1)
# #             nonce = bytes.fromhex(nonce_hex)
# #             ct    = bytes.fromhex(ct_hex)
# #             pt    = aes.decrypt_gcm(nonce, ct)
# #             self.txt_plain.setPlainText(pt.decode("utf-8"))
# #         except Exception as exc:
# #             QMessageBox.warning(self, "Decrypt Error", str(exc))

# #     def _hash(self):
# #         data = self.txt_hash_input.text().encode("utf-8")
# #         if not data:
# #             return
# #         algo = self.cmb_hash.currentText()
# #         if algo == "SHA-256":
# #             result = HashCrypto.sha256(data)
# #         elif algo == "SHA-512":
# #             result = HashCrypto.sha512(data)
# #         else:
# #             result = HashCrypto.blake2b(data)
# #         self.txt_hash_output.setText(result.hex())

# #     def _rsa_test(self):
# #         self.txt_rsa_result.clear()
# #         try:
# #             t0 = time.time()
# #             rsa = RSACrypto(key_size=4096)
# #             rsa.generate_keys()
# #             t1 = time.time()

# #             msg = b"Hello from SecureCrypt RSA test!"
# #             ct  = rsa.encrypt(msg)
# #             pt  = rsa.decrypt(ct)

# #             sig    = rsa.sign(msg)
# #             valid  = rsa.verify(msg, sig)

# #             self.txt_rsa_result.appendPlainText(
# #                 f"Key generation: {t1 - t0:.2f}s"
# #             )
# #             self.txt_rsa_result.appendPlainText(
# #                 f"Plaintext:  {msg.decode()}"
# #             )
# #             self.txt_rsa_result.appendPlainText(
# #                 f"Decrypted:  {pt.decode()}"
# #             )
# #             self.txt_rsa_result.appendPlainText(
# #                 f"Match: {'✅' if pt == msg else '❌'}"
# #             )
# #             self.txt_rsa_result.appendPlainText(
# #                 f"Signature valid: {'✅' if valid else '❌'}"
# #             )
# #         except Exception as exc:
# #             self.txt_rsa_result.appendPlainText(f"Error: {exc}")

# #     def _ecc_test(self):
# #         self.txt_ecc_result.clear()
# #         try:
# #             alice = ECCCrypto("SECP384R1")
# #             alice.generate_keys()
# #             bob = ECCCrypto("SECP384R1")
# #             bob.generate_keys()

# #             key_a = alice.derive_shared_key(bob.public_key)
# #             key_b = bob.derive_shared_key(alice.public_key)

# #             msg = b"ECDH shared-secret test"
# #             sig = alice.sign(msg)
# #             valid = alice.verify(msg, sig)

# #             self.txt_ecc_result.appendPlainText(
# #                 f"Alice shared key: {key_a.hex()[:32]}…"
# #             )
# #             self.txt_ecc_result.appendPlainText(
# #                 f"Bob   shared key: {key_b.hex()[:32]}…"
# #             )
# #             self.txt_ecc_result.appendPlainText(
# #                 f"Keys match: {'✅' if key_a == key_b else '❌'}"
# #             )
# #             self.txt_ecc_result.appendPlainText(
# #                 f"ECDSA signature valid: {'✅' if valid else '❌'}"
# #             )
# #         except Exception as exc:
# #             self.txt_ecc_result.appendPlainText(f"Error: {exc}")


# class CryptoToolsTab(QWidget):
#     """Interactive cipher playground — test all 12 algorithms."""

#     def __init__(self, parent=None):
#         super().__init__(parent)
#         self._build_ui()

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#         #  Cipher Comparison Table
#         # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#         table_group = QGroupBox("📊  Supported Ciphers")
#         table_layout = QVBoxLayout(table_group)

#         self.tbl_ciphers = QTableWidget()
#         headers = [
#             "Cipher", "Key Bits", "Mode", "AEAD",
#             "Security", "Speed",
#         ]
#         self.tbl_ciphers.setColumnCount(len(headers))
#         self.tbl_ciphers.setHorizontalHeaderLabels(headers)
#         self.tbl_ciphers.horizontalHeader().setSectionResizeMode(
#             QHeaderView.ResizeMode.Stretch
#         )
#         self.tbl_ciphers.setEditTriggers(
#             QTableWidget.EditTrigger.NoEditTriggers
#         )

#         # Populate table
#         all_info = CipherFactory.get_all_info()
#         self.tbl_ciphers.setRowCount(len(all_info))
#         for row, info in enumerate(all_info):
#             self.tbl_ciphers.setItem(
#                 row, 0, QTableWidgetItem(info["name"])
#             )
#             self.tbl_ciphers.setItem(
#                 row, 1, QTableWidgetItem(str(info["key_bits"]))
#             )
#             self.tbl_ciphers.setItem(
#                 row, 2, QTableWidgetItem(info["category"])
#             )
#             aead_item = QTableWidgetItem(
#                 "✅ Yes" if info["aead"] else "🔗 HMAC"
#             )
#             self.tbl_ciphers.setItem(row, 3, aead_item)
#             self.tbl_ciphers.setItem(
#                 row, 4, QTableWidgetItem(info["security"])
#             )
#             self.tbl_ciphers.setItem(
#                 row, 5, QTableWidgetItem(info["speed"])
#             )
#         self.tbl_ciphers.setMaximumHeight(250)
#         table_layout.addWidget(self.tbl_ciphers)
#         layout.addWidget(table_group)

#         # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#         #  Encrypt / Decrypt Test Area
#         # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#         enc_group = QGroupBox("🔒  Encrypt / Decrypt Playground")
#         enc_layout = QVBoxLayout(enc_group)

#         # Cipher selector + key
#         row1 = QHBoxLayout()
#         row1.addWidget(QLabel("Cipher:"))
#         self.cmb_cipher = QComboBox()
#         self.cmb_cipher.addItems(CipherFactory.list_ciphers())
#         self.cmb_cipher.currentTextChanged.connect(
#             self._on_cipher_changed
#         )
#         row1.addWidget(self.cmb_cipher)

#         row1.addWidget(QLabel("Key (hex):"))
#         self.txt_key = QLineEdit()
#         self.txt_key.setPlaceholderText("Click Generate")
#         row1.addWidget(self.txt_key)

#         self.btn_gen_key = QPushButton("🔑 Generate")
#         self.btn_gen_key.clicked.connect(self._gen_key)
#         row1.addWidget(self.btn_gen_key)

#         self.lbl_key_info = QLabel("")
#         self.lbl_key_info.setStyleSheet("color: #6c7086;")
#         row1.addWidget(self.lbl_key_info)

#         enc_layout.addLayout(row1)

#         # Plaintext
#         self.txt_plain = QTextEdit()
#         self.txt_plain.setPlaceholderText(
#             "Enter plaintext to encrypt…"
#         )
#         self.txt_plain.setMaximumHeight(80)
#         enc_layout.addWidget(self.txt_plain)

#         # Buttons
#         btn_row = QHBoxLayout()
#         self.btn_encrypt = QPushButton("🔒  Encrypt")
#         self.btn_encrypt.clicked.connect(self._encrypt)
#         btn_row.addWidget(self.btn_encrypt)

#         self.btn_decrypt = QPushButton("🔓  Decrypt")
#         self.btn_decrypt.clicked.connect(self._decrypt)
#         btn_row.addWidget(self.btn_decrypt)
#         enc_layout.addLayout(btn_row)

#         # Ciphertext
#         self.txt_cipher_out = QTextEdit()
#         self.txt_cipher_out.setPlaceholderText(
#             "Encrypted output (hex)…"
#         )
#         self.txt_cipher_out.setMaximumHeight(80)
#         enc_layout.addWidget(self.txt_cipher_out)

#         layout.addWidget(enc_group)

#         # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#         #  Benchmark All Ciphers
#         # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#         bench_group = QGroupBox("⚡  Cipher Benchmark")
#         bench_layout = QVBoxLayout(bench_group)

#         bench_btn_row = QHBoxLayout()
#         self.btn_benchmark = QPushButton(
#             "🏁  Run Benchmark (all ciphers)"
#         )
#         self.btn_benchmark.clicked.connect(self._run_benchmark)
#         bench_btn_row.addWidget(self.btn_benchmark)

#         self.btn_verify = QPushButton(
#             "✅  Verify All Ciphers"
#         )
#         self.btn_verify.clicked.connect(self._verify_all)
#         bench_btn_row.addWidget(self.btn_verify)
#         bench_layout.addLayout(bench_btn_row)

#         self.txt_bench = QPlainTextEdit()
#         self.txt_bench.setReadOnly(True)
#         self.txt_bench.setMaximumHeight(200)
#         self.txt_bench.setFont(MONO_FONT)
#         bench_layout.addWidget(self.txt_bench)
#         layout.addWidget(bench_group)

#         # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#         #  Hash Section
#         # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#         hash_group = QGroupBox("#️⃣  Hashing")
#         hash_layout = QVBoxLayout(hash_group)

#         hash_row = QHBoxLayout()
#         self.txt_hash_in = QLineEdit()
#         self.txt_hash_in.setPlaceholderText("Data to hash…")
#         hash_row.addWidget(self.txt_hash_in)

#         self.cmb_hash = QComboBox()
#         self.cmb_hash.addItems([
#             "SHA-256", "SHA-512", "BLAKE2b",
#         ])
#         hash_row.addWidget(self.cmb_hash)

#         self.btn_hash = QPushButton("#️⃣ Hash")
#         self.btn_hash.clicked.connect(self._hash)
#         hash_row.addWidget(self.btn_hash)
#         hash_layout.addLayout(hash_row)

#         self.txt_hash_out = QLineEdit()
#         self.txt_hash_out.setReadOnly(True)
#         hash_layout.addWidget(self.txt_hash_out)
#         layout.addWidget(hash_group)

#         layout.addStretch()
#         self._on_cipher_changed(self.cmb_cipher.currentText())

#     # ── Key generation ───────────────────────────────────────────

#     def _on_cipher_changed(self, cipher_name: str):
#         if not cipher_name:
#             return
#         info = CipherFactory.get_info(cipher_name)
#         self.lbl_key_info.setText(
#             f"{info['key_bits']}-bit | "
#             f"{info['category']} | "
#             f"{'AEAD' if info['aead'] else 'HMAC auth'}"
#         )

#     def _gen_key(self):
#         """Generate a random 32-byte key (enough for any cipher)."""
#         key = os.urandom(32)
#         self.txt_key.setText(key.hex())

#     def _get_key(self) -> bytes | None:
#         hex_key = self.txt_key.text().strip()
#         if not hex_key:
#             QMessageBox.warning(
#                 self, "No Key",
#                 "Generate or enter a key first.",
#             )
#             return None
#         try:
#             return bytes.fromhex(hex_key)
#         except ValueError:
#             QMessageBox.warning(self, "Bad Key", "Invalid hex.")
#             return None

#     # ── Encrypt / Decrypt ────────────────────────────────────────

#     def _encrypt(self):
#         key = self._get_key()
#         if not key:
#             return
#         pt = self.txt_plain.toPlainText().encode("utf-8")
#         if not pt:
#             return
#         cipher_name = self.cmb_cipher.currentText()
#         try:
#             cipher = CipherFactory.create(cipher_name, key)
#             encrypted = cipher.encrypt(pt)
#             self.txt_cipher_out.setPlainText(encrypted.hex())
#         except Exception as exc:
#             QMessageBox.warning(
#                 self, "Encrypt Error", str(exc)
#             )

#     def _decrypt(self):
#         key = self._get_key()
#         if not key:
#             return
#         hex_ct = self.txt_cipher_out.toPlainText().strip()
#         if not hex_ct:
#             return
#         cipher_name = self.cmb_cipher.currentText()
#         try:
#             ct     = bytes.fromhex(hex_ct)
#             cipher = CipherFactory.create(cipher_name, key)
#             pt     = cipher.decrypt(ct)
#             self.txt_plain.setPlainText(pt.decode("utf-8"))
#         except Exception as exc:
#             QMessageBox.warning(
#                 self, "Decrypt Error", str(exc)
#             )

#     # ── Hash ─────────────────────────────────────────────────────

#     def _hash(self):
#         data = self.txt_hash_in.text().encode("utf-8")
#         if not data:
#             return
#         algo = self.cmb_hash.currentText()
#         if algo == "SHA-256":
#             result = HashCrypto.sha256(data)
#         elif algo == "SHA-512":
#             result = HashCrypto.sha512(data)
#         else:
#             result = HashCrypto.blake2b(data)
#         self.txt_hash_out.setText(result.hex())

#     # ── Verify All Ciphers ───────────────────────────────────────

#     def _verify_all(self):
#         """Encrypt→decrypt round-trip for every cipher."""
#         self.txt_bench.clear()
#         key_material = os.urandom(32)
#         test_data    = b"SecureCrypt verification test! \xf0\x9f\x94\x90"
#         all_pass     = True

#         self.txt_bench.appendPlainText(
#             "═══ Cipher Verification ══════════════════════"
#         )

#         for name in CipherFactory.list_ciphers():
#             try:
#                 cipher    = CipherFactory.create(name, key_material)
#                 encrypted = cipher.encrypt(test_data)
#                 decrypted = cipher.decrypt(encrypted)
#                 overhead  = len(encrypted) - len(test_data)

#                 if decrypted == test_data:
#                     self.txt_bench.appendPlainText(
#                         f"  ✅ {name:25s} — OK  "
#                         f"(overhead: {overhead:3d} bytes, "
#                         f"AEAD: {cipher.is_aead})"
#                     )
#                 else:
#                     self.txt_bench.appendPlainText(
#                         f"  ❌ {name:25s} — DATA MISMATCH"
#                     )
#                     all_pass = False
#             except Exception as exc:
#                 self.txt_bench.appendPlainText(
#                     f"  ❌ {name:25s} — ERROR: {exc}"
#                 )
#                 all_pass = False

#         self.txt_bench.appendPlainText(
#             "═══════════════════════════════════════════════"
#         )
#         if all_pass:
#             self.txt_bench.appendPlainText(
#                 "  🎉  ALL CIPHERS PASSED"
#             )
#         else:
#             self.txt_bench.appendPlainText(
#                 "  ⚠️   SOME CIPHERS FAILED"
#             )

#     # ── Benchmark ────────────────────────────────────────────────

#     def _run_benchmark(self):
#         """
#         Encrypt 1 MB of data with each cipher and measure
#         throughput in MB/s.
#         """
#         import time as _time

#         self.txt_bench.clear()
#         key_material = os.urandom(32)
#         test_data    = os.urandom(1024 * 1024)   # 1 MB

#         self.txt_bench.appendPlainText(
#             "═══ Cipher Benchmark (1 MB) ══════════════════"
#         )
#         self.txt_bench.appendPlainText(
#             f"  {'Cipher':<25s} {'Encrypt':>10s} {'Decrypt':>10s}"
#             f" {'Total':>10s}"
#         )
#         self.txt_bench.appendPlainText("  " + "─" * 58)

#         results = []

#         for name in CipherFactory.list_ciphers():
#             try:
#                 cipher = CipherFactory.create(name, key_material)

#                 # Encrypt benchmark
#                 t0 = _time.perf_counter()
#                 encrypted = cipher.encrypt(test_data)
#                 t_enc = _time.perf_counter() - t0

#                 # Decrypt benchmark
#                 t0 = _time.perf_counter()
#                 decrypted = cipher.decrypt(encrypted)
#                 t_dec = _time.perf_counter() - t0

#                 assert decrypted == test_data

#                 enc_mbps = 1.0 / t_enc if t_enc > 0 else 9999
#                 dec_mbps = 1.0 / t_dec if t_dec > 0 else 9999
#                 total_ms = (t_enc + t_dec) * 1000

#                 results.append((name, enc_mbps, dec_mbps, total_ms))

#                 self.txt_bench.appendPlainText(
#                     f"  {name:<25s} "
#                     f"{enc_mbps:>7.1f}MB/s "
#                     f"{dec_mbps:>7.1f}MB/s "
#                     f"{total_ms:>7.1f}ms"
#                 )
#             except Exception as exc:
#                 self.txt_bench.appendPlainText(
#                     f"  {name:<25s}  ERROR: {exc}"
#                 )

#         # Sort by speed
#         self.txt_bench.appendPlainText(
#             "\n═══ Ranking (fastest first) ═══════════════════"
#         )
#         results.sort(key=lambda x: x[3])
#         for rank, (name, enc, dec, total) in enumerate(results, 1):
#             bar = "█" * max(1, int(50 / (total + 0.1)))
#             self.txt_bench.appendPlainText(
#                 f"  {rank:2d}. {name:<25s} {total:>7.1f}ms "
#                 f"{bar}"
#             )

#         if results:
#             fastest = results[0][0]
#             self.txt_bench.appendPlainText(
#                 f"\n  🏆 Fastest: {fastest}"
#             )
#             recommended = CipherFactory.recommend()
#             self.txt_bench.appendPlainText(
#                 f"  💡 Recommended: {recommended}"
#             )

# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Tab 6 — Key Manager
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# class KeyManagerTab(QWidget):
#     def __init__(self, bridge: SignalBridge, parent=None):
#         super().__init__(parent)
#         self.bridge = bridge
#         self.km = KeyManager()
#         self._build_ui()
#         self._refresh_list()

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         # ── generate ─────────────────────────────────────────────
#         gen_group = QGroupBox("Generate Key Pair")
#         gen_layout = QGridLayout(gen_group)

#         gen_layout.addWidget(QLabel("Name:"), 0, 0)
#         self.txt_name = QLineEdit("server")
#         gen_layout.addWidget(self.txt_name, 0, 1)

#         gen_layout.addWidget(QLabel("Type:"), 0, 2)
#         self.cmb_type = QComboBox()
#         self.cmb_type.addItems(["RSA-4096", "ECC-P384"])
#         gen_layout.addWidget(self.cmb_type, 0, 3)

#         gen_layout.addWidget(QLabel("Password:"), 1, 0)
#         self.txt_pass = QLineEdit()
#         self.txt_pass.setEchoMode(QLineEdit.EchoMode.Password)
#         self.txt_pass.setPlaceholderText("Optional encryption password")
#         gen_layout.addWidget(self.txt_pass, 1, 1, 1, 2)

#         self.btn_generate = QPushButton("🔑  Generate")
#         self.btn_generate.clicked.connect(self._generate)
#         gen_layout.addWidget(self.btn_generate, 1, 3)

#         layout.addWidget(gen_group)

#         # ── key list ─────────────────────────────────────────────
#         list_group = QGroupBox("Keys on Disk")
#         list_layout = QVBoxLayout(list_group)

#         self.tbl_keys = QTableWidget(0, 2)
#         self.tbl_keys.setHorizontalHeaderLabels(["File Name", "Path"])
#         self.tbl_keys.horizontalHeader().setSectionResizeMode(
#             QHeaderView.ResizeMode.Stretch
#         )
#         self.tbl_keys.setEditTriggers(
#             QTableWidget.EditTrigger.NoEditTriggers
#         )
#         list_layout.addWidget(self.tbl_keys)

#         btn_row = QHBoxLayout()
#         self.btn_refresh_keys = QPushButton("🔄  Refresh")
#         self.btn_refresh_keys.clicked.connect(self._refresh_list)
#         btn_row.addWidget(self.btn_refresh_keys)

#         self.btn_delete_key = QPushButton("🗑️  Delete Selected")
#         self.btn_delete_key.setProperty("danger", True)
#         self.btn_delete_key.clicked.connect(self._delete_selected)
#         btn_row.addWidget(self.btn_delete_key)

#         list_layout.addLayout(btn_row)
#         layout.addWidget(list_group)
#         layout.addStretch()

#     def _generate(self):
#         name = self.txt_name.text().strip()
#         if not name:
#             QMessageBox.warning(self, "Error", "Enter a key name.")
#             return
#         pwd = self.txt_pass.text().encode() if self.txt_pass.text() else None
#         ktype = self.cmb_type.currentText()

#         try:
#             if ktype.startswith("RSA"):
#                 priv, pub = self.km.generate_rsa_keypair(
#                     name, key_size=4096, password=pwd
#                 )
#             else:
#                 priv, pub = self.km.generate_ecc_keypair(
#                     name, curve="SECP384R1", password=pwd
#                 )
#             QMessageBox.information(
#                 self, "Success",
#                 f"Keys generated:\n  {priv}\n  {pub}",
#             )
#             self._refresh_list()
#             self.bridge.status_update.emit(
#                 f"{ktype} key pair '{name}' generated"
#             )
#         except Exception as exc:
#             QMessageBox.critical(self, "Error", str(exc))

#     def _refresh_list(self):
#         keys = self.km.list_keys()
#         self.tbl_keys.setRowCount(len(keys))
#         for row, fname in enumerate(keys):
#             self.tbl_keys.setItem(row, 0, QTableWidgetItem(fname))
#             self.tbl_keys.setItem(
#                 row, 1,
#                 QTableWidgetItem(
#                     os.path.join(self.km.keys_dir, fname)
#                 ),
#             )

#     def _delete_selected(self):
#         row = self.tbl_keys.currentRow()
#         if row < 0:
#             QMessageBox.warning(self, "Error", "Select a key to delete.")
#             return
#         fname = self.tbl_keys.item(row, 0).text()
#         reply = QMessageBox.question(
#             self, "Confirm",
#             f"Delete {fname}? This cannot be undone.",
#             QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
#         )
#         if reply == QMessageBox.StandardButton.Yes:
#             path = os.path.join(self.km.keys_dir, fname)
#             try:
#                 os.remove(path)
#                 self._refresh_list()
#                 self.bridge.status_update.emit(f"Deleted {fname}")
#             except Exception as exc:
#                 QMessageBox.critical(self, "Error", str(exc))

#     @property
#     def key_count(self) -> int:
#         return self.tbl_keys.rowCount()


# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Tab 7 — Logs
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# class LogsTab(QWidget):
#     def __init__(self, log_handler: QtLogHandler, parent=None):
#         super().__init__(parent)
#         self.log_handler = log_handler
#         self._build_ui()

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         toolbar = QHBoxLayout()
#         self.chk_auto = QCheckBox("Auto-scroll")
#         self.chk_auto.setChecked(True)
#         toolbar.addWidget(self.chk_auto)

#         self.btn_clear = QPushButton("🗑️  Clear")
#         self.btn_clear.clicked.connect(self._clear)
#         toolbar.addWidget(self.btn_clear)

#         self.btn_save = QPushButton("💾  Save to File")
#         self.btn_save.clicked.connect(self._save)
#         toolbar.addWidget(self.btn_save)

#         toolbar.addStretch()
#         layout.addLayout(toolbar)

#         self.txt_log = QPlainTextEdit()
#         self.txt_log.setReadOnly(True)
#         self.txt_log.setMaximumBlockCount(5000)
#         self.txt_log.setFont(MONO_FONT)
#         layout.addWidget(self.txt_log)

#         # connect log handler
#         self.log_handler.signal_emitter.log_message.connect(
#             self._append_log
#         )

#     def _append_log(self, msg: str):
#         self.txt_log.appendPlainText(msg)
#         if self.chk_auto.isChecked():
#             cursor = self.txt_log.textCursor()
#             cursor.movePosition(QTextCursor.MoveOperation.End)
#             self.txt_log.setTextCursor(cursor)

#     def _clear(self):
#         self.txt_log.clear()

#     def _save(self):
#         path, _ = QFileDialog.getSaveFileName(
#             self, "Save Log", "securecrypt.log", "Log Files (*.log *.txt)"
#         )
#         if path:
#             with open(path, "w") as f:
#                 f.write(self.txt_log.toPlainText())


# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Main Window
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# class MainWindow(QMainWindow):
#     def __init__(self):
#         super().__init__()
#         self.start_time = time.time()
#         self.bridge = SignalBridge()
#         self.log_handler = QtLogHandler()

#         # set up Python logging
#         root_logger = logging.getLogger()
#         root_logger.setLevel(logging.DEBUG)
#         root_logger.addHandler(self.log_handler)

#         # also log to console
#         console_handler = logging.StreamHandler()
#         console_handler.setLevel(logging.DEBUG)
#         console_handler.setFormatter(logging.Formatter(
#             "[%(asctime)s] [%(levelname)-8s] %(name)s — %(message)s",
#             datefmt="%H:%M:%S",
#         ))
#         root_logger.addHandler(console_handler)

#         self.logger = logging.getLogger("SecureCrypt.Main")

#         self._init_window()
#         self._init_tabs()
#         self._init_status_bar()
#         self._init_timers()

#         self.logger.info(
#             "%s v%s started", Settings.APP_NAME, Settings.APP_VERSION
#         )

#     def _init_window(self):
#         self.setWindowTitle(
#             f"{Settings.APP_NAME} — Encrypted Traffic Protection"
#         )
#         self.setMinimumSize(1000, 700)
#         self.resize(1200, 800)

#     def _init_tabs(self):
#         self.tabs = QTabWidget()
#         self.setCentralWidget(self.tabs)

#         self.tab_dashboard     = DashboardTab(self.bridge)
#         self.tab_tunnel_server = TunnelServerTab(self.bridge)
#         self.tab_tunnel_client = TunnelClientTab(self.bridge)
#         self.tab_proxy         = ProxyTab(self.bridge)
#         self.tab_crypto        = CryptoToolsTab()
#         self.tab_keys          = KeyManagerTab(self.bridge)
#         self.tab_logs          = LogsTab(self.log_handler)

#         self.tabs.addTab(self.tab_dashboard,     "📊 Dashboard")
#         self.tabs.addTab(self.tab_tunnel_server, "🖥️ Tunnel Server")
#         self.tabs.addTab(self.tab_tunnel_client, "🔗 Tunnel Client")
#         self.tabs.addTab(self.tab_proxy,         "🌐 Proxy")
#         self.tabs.addTab(self.tab_crypto,        "🔐 Crypto Tools")
#         self.tabs.addTab(self.tab_keys,          "🔑 Key Manager")
#         self.tabs.addTab(self.tab_logs,          "📝 Logs")

#     def _init_status_bar(self):
#         self.status_bar = QStatusBar()
#         self.setStatusBar(self.status_bar)
#         self.status_label = QLabel("Ready")
#         self.status_bar.addPermanentWidget(self.status_label)

#         self.bridge.status_update.connect(self._update_status)

#     def _update_status(self, msg: str):
#         self.status_label.setText(msg)
#         self.logger.info("Status: %s", msg)

#     def _init_timers(self):
#         self.dashboard_timer = QTimer(self)
#         self.dashboard_timer.timeout.connect(self._refresh_dashboard)
#         self.dashboard_timer.start(2000)

#     def _refresh_dashboard(self):
#         self.tab_dashboard.update_status(
#             tunnel_running=self.tab_tunnel_server.is_running,
#             proxy_running=self.tab_proxy.is_running,
#             session_count=self.tab_tunnel_server.session_manager.active_count(),
#             key_count=self.tab_keys.key_count,
#             start_time=self.start_time,
#         )

#     # ── clean shutdown ───────────────────────────────────────────
#     def closeEvent(self, event):
#         self.logger.info("Shutting down…")

#         if self.tab_tunnel_server.is_running:
#             self.tab_tunnel_server.stop_server()

#         if self.tab_tunnel_client.tunnel_client:
#             self.tab_tunnel_client.disconnect_tunnel()

#         if self.tab_proxy.is_running:
#             self.tab_proxy.stop_proxy()

#         self.logger.info("Goodbye!")
#         event.accept()


# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# #  Entry Point
# # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# def main():
#     # Ensure keys directory exists
#     os.makedirs(Settings.KEYS_DIR, exist_ok=True)

#     app = QApplication(sys.argv)
#     app.setApplicationName(Settings.APP_NAME)
#     app.setApplicationVersion(Settings.APP_VERSION)
#     app.setStyleSheet(STYLE_SHEET)

#     window = MainWindow()
#     window.show()

#     sys.exit(app.exec())


# if __name__ == "__main__":
#     main()






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

# import sys
# import os
# import time
# import logging
# import threading
# from datetime import datetime

# from PyQt6.QtWidgets import (
#     QApplication, QMainWindow, QWidget, QTabWidget,
#     QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
#     QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox,
#     QGroupBox, QSpinBox, QFileDialog, QMessageBox,
#     QTableWidget, QTableWidgetItem, QHeaderView,
#     QSplitter, QStatusBar, QCheckBox, QPlainTextEdit,
#     QSizePolicy,
# )
# from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
# from PyQt6.QtGui import QFont, QColor, QIcon, QTextCursor

# # ── SecureCrypt imports ──────────────────────────────────────────
# from config.settings import Settings

# from core.crypto_engine import AESCrypto, RSACrypto, ECCCrypto, HashCrypto

# from utils.random_gen     import SecureRandom
# from utils.key_manager    import KeyManager
# from utils.secure_storage import SecureStorage
# from utils.framing        import Framing, MessageType

# from traffic.handshake       import HandshakeProtocol
# from traffic.session_manager import Session, SessionManager
# from traffic.tunnel_server   import TunnelServer, TunnelClient
# from traffic.proxy_client    import ProxyServer




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

# class DashboardTab(QWidget):
#     def __init__(self, bridge: SignalBridge, parent=None):
#         super().__init__(parent)
#         self.bridge = bridge
#         self._build_ui()

#         # refresh every 2 seconds
#         self._timer = QTimer(self)
#         self._timer.timeout.connect(self.refresh)
#         self._timer.start(2000)

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         # ── header ───────────────────────────────────────────────
#         header = QLabel(f"🔐  {Settings.APP_NAME}  v{Settings.APP_VERSION}")
#         header.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
#         header.setAlignment(Qt.AlignmentFlag.AlignCenter)
#         header.setStyleSheet("color: #89b4fa; padding: 16px;")
#         layout.addWidget(header)

#         subtitle = QLabel(
#             "End-to-end encrypted traffic protection"
#         )
#         subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
#         subtitle.setStyleSheet("color: #6c7086; font-size: 13px;")
#         layout.addWidget(subtitle)

#         # ── status cards ─────────────────────────────────────────
#         cards_layout = QHBoxLayout()

#         self.card_tunnel = self._make_card("Tunnel Server", "⏹ Stopped")
#         self.card_proxy  = self._make_card("Proxy Server",  "⏹ Stopped")
#         self.card_sessions = self._make_card("Active Sessions", "0")
#         self.card_keys   = self._make_card("Keys on Disk", "—")

#         cards_layout.addWidget(self.card_tunnel)
#         cards_layout.addWidget(self.card_proxy)
#         cards_layout.addWidget(self.card_sessions)
#         cards_layout.addWidget(self.card_keys)
#         layout.addLayout(cards_layout)

#         # ── info group ───────────────────────────────────────────
#         info_group = QGroupBox("System Information")
#         info_layout = QFormLayout(info_group)

#         self.lbl_tunnel_addr = QLabel("—")
#         self.lbl_proxy_addr  = QLabel("—")
#         self.lbl_cipher      = QLabel(Settings.DEFAULT_CIPHER)
#         self.lbl_uptime      = QLabel("—")

#         info_layout.addRow("Tunnel Address:", self.lbl_tunnel_addr)
#         info_layout.addRow("Proxy Address:",  self.lbl_proxy_addr)
#         info_layout.addRow("Default Cipher:", self.lbl_cipher)
#         info_layout.addRow("Uptime:",         self.lbl_uptime)
#         layout.addWidget(info_group)

#         layout.addStretch()

#     def _make_card(self, title: str, value: str) -> QGroupBox:
#         card = QGroupBox(title)
#         card.setFixedHeight(100)
#         vl = QVBoxLayout(card)
#         lbl = QLabel(value)
#         lbl.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
#         lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
#         lbl.setObjectName("card_value")
#         vl.addWidget(lbl)
#         return card

#     def _card_value(self, card: QGroupBox) -> QLabel:
#         return card.findChild(QLabel, "card_value")

#     def refresh(self):
#         """Called by parent window with live state."""
#         pass  # filled in by MainWindow

#     def update_status(
#         self,
#         tunnel_running: bool,
#         proxy_running: bool,
#         session_count: int,
#         key_count: int,
#         start_time: float,
#     ):
#         self._card_value(self.card_tunnel).setText(
#             "✅ Running" if tunnel_running else "⏹ Stopped"
#         )
#         self._card_value(self.card_proxy).setText(
#             "✅ Running" if proxy_running else "⏹ Stopped"
#         )
#         self._card_value(self.card_sessions).setText(str(session_count))
#         self._card_value(self.card_keys).setText(str(key_count))

#         if tunnel_running:
#             self.lbl_tunnel_addr.setText(
#                 f"{Settings.TUNNEL_HOST}:{Settings.TUNNEL_PORT}"
#             )
#         else:
#             self.lbl_tunnel_addr.setText("—")

#         if proxy_running:
#             self.lbl_proxy_addr.setText(
#                 f"{Settings.PROXY_HOST}:{Settings.PROXY_PORT}"
#             )
#         else:
#             self.lbl_proxy_addr.setText("—")

#         elapsed = int(time.time() - start_time)
#         h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
#         self.lbl_uptime.setText(f"{h:02d}:{m:02d}:{s:02d}")

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

# class TunnelServerTab(QWidget):
#     def __init__(self, bridge: SignalBridge, parent=None):
#         super().__init__(parent)
#         self.bridge = bridge
#         self.tunnel_server: TunnelServer | None = None
#         self.session_manager = SessionManager(
#             timeout=Settings.SESSION_TIMEOUT
#         )
#         self._build_ui()

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         # ── config ───────────────────────────────────────────────
#         config_group = QGroupBox("Server Configuration")
#         config_layout = QGridLayout(config_group)

#         config_layout.addWidget(QLabel("Bind Host:"), 0, 0)
#         self.txt_host = QLineEdit(Settings.TUNNEL_HOST)
#         config_layout.addWidget(self.txt_host, 0, 1)

#         config_layout.addWidget(QLabel("Bind Port:"), 0, 2)
#         self.spn_port = QSpinBox()
#         self.spn_port.setRange(1, 65535)
#         self.spn_port.setValue(Settings.TUNNEL_PORT)
#         config_layout.addWidget(self.spn_port, 0, 3)

#         config_layout.addWidget(QLabel("Server ID:"), 1, 0)
#         self.txt_server_id = QLineEdit("securecrypt-server")
#         config_layout.addWidget(self.txt_server_id, 1, 1)

#         config_layout.addWidget(QLabel("Forward Host:"), 1, 2)
#         self.txt_fwd_host = QLineEdit("")
#         self.txt_fwd_host.setPlaceholderText("Optional (e.g. 127.0.0.1)")
#         config_layout.addWidget(self.txt_fwd_host, 1, 3)

#         config_layout.addWidget(QLabel("Forward Port:"), 2, 0)
#         self.spn_fwd_port = QSpinBox()
#         self.spn_fwd_port.setRange(0, 65535)
#         self.spn_fwd_port.setValue(0)
#         config_layout.addWidget(self.spn_fwd_port, 2, 1)

#         layout.addWidget(config_group)

#         # ── controls ─────────────────────────────────────────────
#         btn_layout = QHBoxLayout()
#         self.btn_start = QPushButton("▶  Start Server")
#         self.btn_start.clicked.connect(self.start_server)
#         btn_layout.addWidget(self.btn_start)

#         self.btn_stop = QPushButton("⏹  Stop Server")
#         self.btn_stop.setProperty("danger", True)
#         self.btn_stop.setEnabled(False)
#         self.btn_stop.clicked.connect(self.stop_server)
#         btn_layout.addWidget(self.btn_stop)

#         self.btn_refresh = QPushButton("🔄  Refresh Sessions")
#         self.btn_refresh.clicked.connect(self.refresh_sessions)
#         btn_layout.addWidget(self.btn_refresh)

#         layout.addLayout(btn_layout)

#         # ── session table ────────────────────────────────────────
#         sessions_group = QGroupBox("Active Sessions")
#         sessions_layout = QVBoxLayout(sessions_group)

#         self.tbl_sessions = QTableWidget(0, 7)
#         self.tbl_sessions.setHorizontalHeaderLabels([
#             "Session ID", "Peer", "Cipher", "Created",
#             "Last Activity", "Sent", "Received",
#         ])
#         self.tbl_sessions.horizontalHeader().setSectionResizeMode(
#             QHeaderView.ResizeMode.Stretch
#         )
#         self.tbl_sessions.setEditTriggers(
#             QTableWidget.EditTrigger.NoEditTriggers
#         )
#         sessions_layout.addWidget(self.tbl_sessions)
#         layout.addWidget(sessions_group)

#         # connect signals
#         self.bridge.session_created.connect(self._on_session_created)
#         self.bridge.session_closed.connect(self._on_session_closed)

#     def start_server(self):
#         try:
#             fwd_host = self.txt_fwd_host.text().strip() or None
#             fwd_port = self.spn_fwd_port.value() or None

#             self.tunnel_server = TunnelServer(
#                 host=self.txt_host.text().strip(),
#                 port=self.spn_port.value(),
#                 forward_host=fwd_host,
#                 forward_port=fwd_port,
#                 session_manager=self.session_manager,
#                 server_id=self.txt_server_id.text().strip(),
#                 on_session_created=self._cb_session_created,
#                 on_session_closed=self._cb_session_closed,
#                 on_data_received=self._cb_data_received,
#             )
#             self.tunnel_server.start()

#             self.btn_start.setEnabled(False)
#             self.btn_stop.setEnabled(True)
#             self.txt_host.setEnabled(False)
#             self.spn_port.setEnabled(False)
#             self.bridge.status_update.emit("Tunnel server started")

#         except Exception as exc:
#             QMessageBox.critical(self, "Error", str(exc))

#     def stop_server(self):
#         if self.tunnel_server:
#             self.tunnel_server.stop()
#             self.tunnel_server = None
#         self.btn_start.setEnabled(True)
#         self.btn_stop.setEnabled(False)
#         self.txt_host.setEnabled(True)
#         self.spn_port.setEnabled(True)
#         self.tbl_sessions.setRowCount(0)
#         self.bridge.status_update.emit("Tunnel server stopped")

#     def refresh_sessions(self):
#         infos = self.session_manager.all_info()
#         self.tbl_sessions.setRowCount(len(infos))
#         for row, info in enumerate(infos):
#             self.tbl_sessions.setItem(
#                 row, 0, QTableWidgetItem(info["session_id"][:16] + "…")
#             )
#             self.tbl_sessions.setItem(
#                 row, 1, QTableWidgetItem(info["peer"])
#             )
#             self.tbl_sessions.setItem(
#                 row, 2, QTableWidgetItem(info["cipher"])
#             )
#             self.tbl_sessions.setItem(
#                 row, 3, QTableWidgetItem(
#                     datetime.fromtimestamp(
#                         info["created"]
#                     ).strftime("%H:%M:%S")
#                 )
#             )
#             self.tbl_sessions.setItem(
#                 row, 4, QTableWidgetItem(
#                     datetime.fromtimestamp(
#                         info["last_activity"]
#                     ).strftime("%H:%M:%S")
#                 )
#             )
#             self.tbl_sessions.setItem(
#                 row, 5, QTableWidgetItem(
#                     self._fmt_bytes(info["bytes_sent"])
#                 )
#             )
#             self.tbl_sessions.setItem(
#                 row, 6, QTableWidgetItem(
#                     self._fmt_bytes(info["bytes_received"])
#                 )
#             )

#     @staticmethod
#     def _fmt_bytes(n: int) -> str:
#         for unit in ("B", "KB", "MB", "GB"):
#             if n < 1024:
#                 return f"{n:.1f} {unit}"
#             n /= 1024
#         return f"{n:.1f} TB"

#     # ── thread-safe callbacks ────────────────────────────────────
#     def _cb_session_created(self, session: Session):
#         self.bridge.session_created.emit(session.info())

#     def _cb_session_closed(self, sid: str):
#         self.bridge.session_closed.emit(sid)

#     def _cb_data_received(self, sid: str, data: bytes):
#         self.bridge.data_received.emit(sid, len(data))

#     def _on_session_created(self, info: dict):
#         self.refresh_sessions()

#     def _on_session_closed(self, sid: str):
#         self.refresh_sessions()

#     @property
#     def is_running(self) -> bool:
#         return self.tunnel_server is not None and self.tunnel_server.is_running

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

# class TunnelClientTab(QWidget):
#     def __init__(self, bridge: SignalBridge, parent=None):
#         super().__init__(parent)
#         self.bridge = bridge
#         self.tunnel_client: TunnelClient | None = None
#         self._build_ui()

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         # ── connection settings ──────────────────────────────────
#         conn_group = QGroupBox("Remote Tunnel Server")
#         conn_layout = QGridLayout(conn_group)

#         conn_layout.addWidget(QLabel("Remote Host:"), 0, 0)
#         self.txt_remote_host = QLineEdit("127.0.0.1")
#         conn_layout.addWidget(self.txt_remote_host, 0, 1)

#         conn_layout.addWidget(QLabel("Remote Port:"), 0, 2)
#         self.spn_remote_port = QSpinBox()
#         self.spn_remote_port.setRange(1, 65535)
#         self.spn_remote_port.setValue(Settings.TUNNEL_PORT)
#         conn_layout.addWidget(self.spn_remote_port, 0, 3)

#         conn_layout.addWidget(QLabel("Local Listen Host:"), 1, 0)
#         self.txt_local_host = QLineEdit("127.0.0.1")
#         self.txt_local_host.setPlaceholderText("Optional")
#         conn_layout.addWidget(self.txt_local_host, 1, 1)

#         conn_layout.addWidget(QLabel("Local Listen Port:"), 1, 2)
#         self.spn_local_port = QSpinBox()
#         self.spn_local_port.setRange(0, 65535)
#         self.spn_local_port.setValue(0)
#         conn_layout.addWidget(self.spn_local_port, 1, 3)

#         layout.addWidget(conn_group)

#         # ── buttons ──────────────────────────────────────────────
#         btn_layout = QHBoxLayout()

#         self.btn_connect = QPushButton("🔗  Connect")
#         self.btn_connect.clicked.connect(self.connect_tunnel)
#         btn_layout.addWidget(self.btn_connect)

#         self.btn_disconnect = QPushButton("❌  Disconnect")
#         self.btn_disconnect.setProperty("danger", True)
#         self.btn_disconnect.setEnabled(False)
#         self.btn_disconnect.clicked.connect(self.disconnect_tunnel)
#         btn_layout.addWidget(self.btn_disconnect)

#         layout.addLayout(btn_layout)

#         # ── session info ─────────────────────────────────────────
#         info_group = QGroupBox("Session Info")
#         info_layout = QFormLayout(info_group)

#         self.lbl_status   = QLabel("Disconnected")
#         self.lbl_sess_id  = QLabel("—")
#         self.lbl_cipher   = QLabel("—")
#         self.lbl_sent     = QLabel("0 B")
#         self.lbl_recv     = QLabel("0 B")

#         info_layout.addRow("Status:",     self.lbl_status)
#         info_layout.addRow("Session ID:", self.lbl_sess_id)
#         info_layout.addRow("Cipher:",     self.lbl_cipher)
#         info_layout.addRow("Sent:",       self.lbl_sent)
#         info_layout.addRow("Received:",   self.lbl_recv)
#         layout.addWidget(info_group)

#         # ── send test data ───────────────────────────────────────
#         test_group = QGroupBox("Send Test Data")
#         test_layout = QHBoxLayout(test_group)

#         self.txt_test_msg = QLineEdit()
#         self.txt_test_msg.setPlaceholderText(
#             "Type a message to send through the encrypted tunnel…"
#         )
#         test_layout.addWidget(self.txt_test_msg)

#         self.btn_send = QPushButton("📤 Send")
#         self.btn_send.setEnabled(False)
#         self.btn_send.clicked.connect(self.send_test)
#         test_layout.addWidget(self.btn_send)
#         layout.addWidget(test_group)

#         layout.addStretch()

#         # refresh timer
#         self._timer = QTimer(self)
#         self._timer.timeout.connect(self._refresh_info)
#         self._timer.start(1000)

#     def connect_tunnel(self):
#         def _do_connect():
#             try:
#                 local_host = self.txt_local_host.text().strip() or None
#                 local_port = self.spn_local_port.value() or None

#                 self.tunnel_client = TunnelClient(
#                     remote_host=self.txt_remote_host.text().strip(),
#                     remote_port=self.spn_remote_port.value(),
#                     local_listen_host=local_host,
#                     local_listen_port=local_port,
#                     on_session_created=lambda s: (
#                         self.bridge.session_created.emit(s.info())
#                     ),
#                     on_session_closed=lambda sid: (
#                         self.bridge.session_closed.emit(sid)
#                     ),
#                 )
#                 self.tunnel_client.connect()

#                 if local_host and local_port:
#                     self.tunnel_client.start_local_listener()
#                 self.tunnel_client.start_keepalive()

#                 self.bridge.status_update.emit(
#                     "Connected to tunnel server"
#                 )
#             except Exception as exc:
#                 self.bridge.status_update.emit(f"Connect failed: {exc}")

#         self.btn_connect.setEnabled(False)
#         threading.Thread(target=_do_connect, daemon=True).start()

#     def disconnect_tunnel(self):
#         if self.tunnel_client:
#             self.tunnel_client.disconnect()
#             self.tunnel_client = None
#         self.btn_connect.setEnabled(True)
#         self.btn_disconnect.setEnabled(False)
#         self.btn_send.setEnabled(False)
#         self.lbl_status.setText("Disconnected")
#         self.lbl_sess_id.setText("—")
#         self.lbl_cipher.setText("—")
#         self.bridge.status_update.emit("Disconnected from tunnel")

#     def send_test(self):
#         msg = self.txt_test_msg.text().strip()
#         if not msg or not self.tunnel_client:
#             return
#         try:
#             self.tunnel_client.send(msg.encode("utf-8"))
#             self.txt_test_msg.clear()
#             self.bridge.status_update.emit(
#                 f"Sent {len(msg)} bytes"
#             )
#         except Exception as exc:
#             QMessageBox.warning(self, "Send Error", str(exc))

#     def _refresh_info(self):
#         if (
#             self.tunnel_client
#             and self.tunnel_client.is_connected
#         ):
#             self.btn_connect.setEnabled(False)
#             self.btn_disconnect.setEnabled(True)
#             self.btn_send.setEnabled(True)
#             self.lbl_status.setText("🟢 Connected")
#             info = self.tunnel_client.session_info
#             if info:
#                 self.lbl_sess_id.setText(info["session_id"][:16] + "…")
#                 self.lbl_cipher.setText(info["cipher"])
#                 self.lbl_sent.setText(
#                     TunnelServerTab._fmt_bytes(info["bytes_sent"])
#                 )
#                 self.lbl_recv.setText(
#                     TunnelServerTab._fmt_bytes(info["bytes_received"])
#                 )
#         else:
#             if not self.btn_connect.isEnabled():
#                 self.btn_connect.setEnabled(True)
#                 self.btn_disconnect.setEnabled(False)
#                 self.btn_send.setEnabled(False)


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

# class ProxyTab(QWidget):
#     def __init__(self, bridge: SignalBridge, parent=None):
#         super().__init__(parent)
#         self.bridge = bridge
#         self.proxy_server: ProxyServer | None = None
#         self._build_ui()

#     def _build_ui(self):
#         layout = QVBoxLayout(self)

#         # ── config ───────────────────────────────────────────────
#         config_group = QGroupBox("Proxy Configuration")
#         config_layout = QGridLayout(config_group)

#         config_layout.addWidget(QLabel("Listen Host:"), 0, 0)
#         self.txt_host = QLineEdit(Settings.PROXY_HOST)
#         config_layout.addWidget(self.txt_host, 0, 1)

#         config_layout.addWidget(QLabel("Listen Port:"), 0, 2)
#         self.spn_port = QSpinBox()
#         self.spn_port.setRange(1, 65535)
#         self.spn_port.setValue(Settings.PROXY_PORT)
#         config_layout.addWidget(self.spn_port, 0, 3)

#         layout.addWidget(config_group)

#         # ── buttons ──────────────────────────────────────────────
#         btn_layout = QHBoxLayout()
#         self.btn_start = QPushButton("▶  Start Proxy")
#         self.btn_start.clicked.connect(self.start_proxy)
#         btn_layout.addWidget(self.btn_start)

#         self.btn_stop = QPushButton("⏹  Stop Proxy")
#         self.btn_stop.setProperty("danger", True)
#         self.btn_stop.setEnabled(False)
#         self.btn_stop.clicked.connect(self.stop_proxy)
#         btn_layout.addWidget(self.btn_stop)

#         layout.addLayout(btn_layout)

#         # ── info ─────────────────────────────────────────────────
#         info_group = QGroupBox("Proxy Info")
#         info_fl = QFormLayout(info_group)
#         self.lbl_status   = QLabel("⏹ Stopped")
#         self.lbl_requests = QLabel("0")
#         self.lbl_active   = QLabel("0")
#         self.lbl_tunnel   = QLabel("❌ No tunnel")
#         info_fl.addRow("Status:",             self.lbl_status)
#         info_fl.addRow("Total Requests:",     self.lbl_requests)
#         info_fl.addRow("Active Connections:", self.lbl_active)
#         info_fl.addRow("Tunnel Encryption:", self.lbl_tunnel)
#         layout.addWidget(info_group)

#         # ── request log ──────────────────────────────────────────
#         log_group = QGroupBox("Recent Requests")
#         log_layout = QVBoxLayout(log_group)
#         self.txt_log = QPlainTextEdit()
#         self.txt_log.setReadOnly(True)
#         self.txt_log.setMaximumBlockCount(500)
#         log_layout.addWidget(self.txt_log)
#         layout.addWidget(log_group)

#         # ── browser hint ─────────────────────────────────────────
#         hint = QLabel(
#             "💡 Set your browser proxy to "
#             f"{Settings.PROXY_HOST}:{Settings.PROXY_PORT} "
#             "to route traffic through SecureCrypt."
#         )
#         hint.setStyleSheet("color: #f9e2af; padding: 8px;")
#         hint.setWordWrap(True)
#         layout.addWidget(hint)

#         # signals
#         self.bridge.proxy_request.connect(self._on_proxy_request)

#         # timer
#         self._timer = QTimer(self)
#         self._timer.timeout.connect(self._refresh_stats)
#         self._timer.start(1000)

#     def start_proxy(self):
#         try:
#             self.proxy_server = ProxyServer(
#                 host=self.txt_host.text().strip(),
#                 port=self.spn_port.value(),
#                 on_request=self._cb_request,
#             )
#             self.proxy_server.start()
#             self.btn_start.setEnabled(False)
#             self.btn_stop.setEnabled(True)
#             self.txt_host.setEnabled(False)
#             self.spn_port.setEnabled(False)
#             self.lbl_status.setText("✅ Running")
#             self.bridge.status_update.emit("Proxy server started")
#         except Exception as exc:
#             QMessageBox.critical(self, "Error", str(exc))

#     def stop_proxy(self):
#         if self.proxy_server:
#             self.proxy_server.stop()
#             self.proxy_server = None
#         self.btn_start.setEnabled(True)
#         self.btn_stop.setEnabled(False)
#         self.txt_host.setEnabled(True)
#         self.spn_port.setEnabled(True)
#         self.lbl_status.setText("⏹ Stopped")
#         self.bridge.status_update.emit("Proxy server stopped")

#     def attach_tunnel_session(self, session: Session | None):
#         if self.proxy_server:
#             self.proxy_server.tunnel_session = session

#     def _cb_request(self, method: str, host: str, port: int):
#         self.bridge.proxy_request.emit(method, host, port)

#     def _on_proxy_request(self, method: str, host: str, port: int):
#         ts = datetime.now().strftime("%H:%M:%S")
#         self.txt_log.appendPlainText(
#             f"[{ts}]  {method}  {host}:{port}"
#         )

#     def _refresh_stats(self):
#         if self.proxy_server and self.proxy_server.is_running:
#             stats = self.proxy_server.stats()
#             self.lbl_requests.setText(str(stats["total_requests"]))
#             self.lbl_active.setText(str(stats["active_connections"]))
#             self.lbl_tunnel.setText(
#                 "✅ Encrypted" if stats["tunnel_active"]
#                 else "❌ Direct"
#             )

#     @property
#     def is_running(self) -> bool:
#         return (
#             self.proxy_server is not None
#             and self.proxy_server.is_running
#         )

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
#  Tab 8 — Cipher Selector
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