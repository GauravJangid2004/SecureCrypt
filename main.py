
"""
SecureCrypt — Main Entry Point & PyQt6 GUI  (IMPROVED UI)

Key improvements over original:
  • Every tab is wrapped in QScrollArea — content never gets clipped
  • Consistent section headers with coloured left-border accents
  • Splitter-based layouts where panels need to resize independently
  • Proper minimum sizes / size policies so nothing is forced tiny
  • Group-box titles rendered at a readable weight/size
  • Status bar shows cipher + connection state at all times
  • Tabs have icons as well as text labels
  • E2E tab: LAN-IP banner, auto peer-refresh, connection status colour
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
    QAbstractItemView, QScrollArea, QFrame, QProgressBar,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QSize
from PyQt6.QtGui import QFont, QColor, QIcon, QTextCursor, QPalette

from config.settings import Settings
from core.crypto_engine import (
    AESCrypto, RSACrypto, ECCCrypto, HashCrypto,
    CipherFactory,
)
from utils.random_gen import SecureRandom
from utils.key_manager import KeyManager
from utils.secure_storage import SecureStorage
from utils.framing import Framing, MessageType
from traffic.handshake import HandshakeProtocol
from traffic.session_manager import Session, SessionManager
from traffic.tunnel_server import TunnelServer, TunnelClient
from traffic.proxy_client import ProxyServer, SystemProxyConfig
from traffic.relay_server import RelayServer
from traffic.peer_client import PeerClient
from core.e2e_engine import E2EEngine
from core.file_transfer import FileMetadata


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _get_local_ip() -> str:
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def make_scroll(widget: QWidget) -> QScrollArea:
    """Wrap *widget* in a QScrollArea with matching dark background."""
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setWidget(widget)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setStyleSheet(
        "QScrollArea { background: transparent; border: none; }"
        "QScrollBar:vertical { background:#1e1e2e; width:10px; border-radius:5px; }"
        "QScrollBar::handle:vertical { background:#45475a; border-radius:5px; min-height:30px; }"
        "QScrollBar::handle:vertical:hover { background:#585b70; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }"
        "QScrollBar:horizontal { background:#1e1e2e; height:10px; border-radius:5px; }"
        "QScrollBar::handle:horizontal { background:#45475a; border-radius:5px; min-width:30px; }"
        "QScrollBar::handle:horizontal:hover { background:#585b70; }"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:0; }"
    )
    return scroll


def section_label(text: str, colour: str = "#89b4fa") -> QLabel:
    """Bold coloured section heading."""
    lbl = QLabel(text)
    lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
    lbl.setStyleSheet(
        f"color:{colour}; border-left:3px solid {colour}; "
        f"padding-left:8px; margin-top:6px; margin-bottom:2px;"
    )
    return lbl


# ──────────────────────────────────────────────────────────────────────────────
# Qt Log Handler
# ──────────────────────────────────────────────────────────────────────────────

class QtLogSignal(QObject):
    log_message = pyqtSignal(str)


class QtLogHandler(logging.Handler):
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


# ──────────────────────────────────────────────────────────────────────────────
# Signal Bridge
# ──────────────────────────────────────────────────────────────────────────────

class SignalBridge(QObject):
    session_created = pyqtSignal(dict)
    session_closed  = pyqtSignal(str)
    data_received   = pyqtSignal(str, int)
    proxy_request   = pyqtSignal(str, str, int)
    status_update   = pyqtSignal(str)


# ──────────────────────────────────────────────────────────────────────────────
# Stylesheet
# ──────────────────────────────────────────────────────────────────────────────

STYLE_SHEET = """
/* ── Base ── */
QMainWindow, QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}

/* ── Tabs ── */
QTabWidget::pane {
    border: 1px solid #313244;
    background-color: #1e1e2e;
    border-radius: 0 8px 8px 8px;
}
QTabBar::tab {
    background-color: #181825;
    color: #a6adc8;
    padding: 9px 18px;
    margin-right: 2px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    font-size: 12px;
    min-width: 90px;
}
QTabBar::tab:selected {
    background-color: #1e1e2e;
    color: #cba6f7;
    font-weight: bold;
    border-bottom: 2px solid #cba6f7;
}
QTabBar::tab:hover:!selected {
    background-color: #313244;
    color: #cdd6f4;
}

/* ── Group Boxes ── */
QGroupBox {
    color: #89b4fa;
    border: 1px solid #313244;
    border-radius: 10px;
    margin-top: 14px;
    padding: 14px 10px 10px 10px;
    font-size: 12px;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 8px;
    background: #1e1e2e;
}

/* ── Buttons ── */
QPushButton {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    padding: 7px 16px;
    border-radius: 7px;
    font-weight: bold;
    font-size: 12px;
    min-height: 30px;
}
QPushButton:hover  { background-color: #45475a; border-color: #89b4fa; color: #89b4fa; }
QPushButton:pressed { background-color: #585b70; }
QPushButton:disabled { background-color: #1e1e2e; color: #45475a; border-color: #313244; }

QPushButton[role="primary"] {
    background-color: #89b4fa;
    color: #1e1e2e;
    border: none;
}
QPushButton[role="primary"]:hover { background-color: #74c7ec; }

QPushButton[role="danger"] {
    background-color: #313244;
    color: #f38ba8;
    border-color: #f38ba8;
}
QPushButton[role="danger"]:hover { background-color: #3d1f27; }

QPushButton[role="success"] {
    background-color: #313244;
    color: #a6e3a1;
    border-color: #a6e3a1;
}
QPushButton[role="success"]:hover { background-color: #1e3a2e; }

/* ── Inputs ── */
QLineEdit, QSpinBox, QComboBox {
    background-color: #181825;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 6px 10px;
    min-height: 28px;
    selection-background-color: #45475a;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border: 1px solid #89b4fa;
    background-color: #1e1e2e;
}
QLineEdit::placeholder { color: #585b70; }
QComboBox::drop-down { border: none; width: 20px; }
QComboBox QAbstractItemView {
    background: #181825;
    border: 1px solid #45475a;
    selection-background-color: #45475a;
    color: #cdd6f4;
}

/* ── Text areas ── */
QTextEdit, QPlainTextEdit {
    background-color: #11111b;
    color: #a6e3a1;
    border: 1px solid #313244;
    border-radius: 6px;
    font-family: "Cascadia Code", "Consolas", "Courier New", monospace;
    font-size: 12px;
    padding: 6px;
}

/* ── Tables ── */
QTableWidget {
    background-color: #181825;
    color: #cdd6f4;
    gridline-color: #313244;
    border: 1px solid #313244;
    border-radius: 6px;
    alternate-background-color: #1e1e2e;
}
QTableWidget::item { padding: 5px 8px; }
QTableWidget::item:selected { background-color: #45475a; color: #cdd6f4; }
QHeaderView::section {
    background-color: #181825;
    color: #89b4fa;
    padding: 7px 8px;
    border: none;
    border-right: 1px solid #313244;
    border-bottom: 1px solid #313244;
    font-weight: bold;
    font-size: 12px;
}

/* ── Lists ── */
QListWidget {
    background-color: #181825;
    border: 1px solid #313244;
    border-radius: 6px;
    color: #cdd6f4;
    padding: 4px;
}
QListWidget::item { padding: 5px 8px; border-radius: 4px; }
QListWidget::item:selected { background: #45475a; }
QListWidget::item:hover { background: #313244; }

/* ── Labels ── */
QLabel { color: #cdd6f4; }

/* ── Status bar ── */
QStatusBar {
    background-color: #11111b;
    color: #a6adc8;
    border-top: 1px solid #313244;
    font-size: 11px;
}

/* ── Checkboxes ── */
QCheckBox { color: #cdd6f4; spacing: 6px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #45475a;
    border-radius: 4px;
    background: #181825;
}
QCheckBox::indicator:checked {
    background: #89b4fa;
    border-color: #89b4fa;
}

/* ── Progress bar ── */
QProgressBar {
    border: 1px solid #313244;
    border-radius: 5px;
    background: #181825;
    text-align: center;
    color: #cdd6f4;
    font-size: 11px;
}
QProgressBar::chunk { background: #89b4fa; border-radius: 5px; }

/* ── Splitter ── */
QSplitter::handle { background: #313244; }
QSplitter::handle:horizontal { width: 2px; }
QSplitter::handle:vertical   { height: 2px; }

/* ── Scroll area ── */
QScrollArea { border: none; background: transparent; }
"""

MONO_FONT   = QFont("Cascadia Code", 10)
MONO_FONT.setStyleHint(QFont.StyleHint.Monospace)
HEADER_FONT = QFont("Segoe UI", 22, QFont.Weight.Bold)
LABEL_FONT  = QFont("Segoe UI", 11)


# ──────────────────────────────────────────────────────────────────────────────
# Reusable: Cipher Selector Widget
# ──────────────────────────────────────────────────────────────────────────────

class CipherSelectorWidget(QGroupBox):
    cipher_changed = pyqtSignal()

    def __init__(self, title: str = "Cipher Selection", parent=None):
        super().__init__(title, parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Preferred cipher row
        pref_row = QHBoxLayout()
        pref_row.addWidget(QLabel("Preferred:"))
        self.cmb_preferred = QComboBox()
        self.cmb_preferred.addItems(CipherFactory.list_ciphers())
        self.cmb_preferred.setCurrentText("AES-256-GCM")
        self.cmb_preferred.currentTextChanged.connect(self._on_preferred_changed)
        pref_row.addWidget(self.cmb_preferred, 1)
        self.lbl_info = QLabel("")
        self.lbl_info.setStyleSheet("color:#6c7086; font-size:11px;")
        pref_row.addWidget(self.lbl_info)
        layout.addLayout(pref_row)

        # Quick-select buttons
        btn_row = QHBoxLayout()
        for label, slot in [
            ("All",         self._select_all),
            ("AEAD only",   self._select_aead_only),
            ("Fastest",     self._select_fastest),
            ("Most Secure", self._select_most_secure),
            ("Clear",       self._clear_all),
        ]:
            b = QPushButton(label)
            b.setFixedHeight(26)
            b.setStyleSheet("font-size:11px; padding:2px 8px;")
            b.clicked.connect(slot)
            btn_row.addWidget(b)
        layout.addLayout(btn_row)

        # Cipher checklist
        self.lst_ciphers = QListWidget()
        self.lst_ciphers.setMinimumHeight(160)
        self.lst_ciphers.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        for info in CipherFactory.get_all_info():
            item = QListWidgetItem()
            cb = QCheckBox(
                f"{info['name']:<22}  {info['key_bits']:>3d}-bit  "
                f"{info['category']:<14}  {info['security']}"
            )
            cb.setFont(QFont("Cascadia Code", 10))
            cb.setChecked(True)
            cb.setProperty("cipher_name", info["name"])
            cb.stateChanged.connect(lambda _: self.cipher_changed.emit())
            self.lst_ciphers.addItem(item)
            self.lst_ciphers.setItemWidget(item, cb)
            item.setSizeHint(QSize(0, 28))
        layout.addWidget(self.lst_ciphers)
        self._on_preferred_changed(self.cmb_preferred.currentText())

    # ── getters ──
    def get_preferred_cipher(self) -> str:
        return self.cmb_preferred.currentText()

    def get_allowed_ciphers(self) -> list[str]:
        result = []
        preferred = self.cmb_preferred.currentText()
        if preferred and self._is_checked(preferred):
            result.append(preferred)
        for i in range(self.lst_ciphers.count()):
            cb = self.lst_ciphers.itemWidget(self.lst_ciphers.item(i))
            if isinstance(cb, QCheckBox) and cb.isChecked():
                name = cb.property("cipher_name")
                if name and name not in result:
                    result.append(name)
        return result or ["AES-256-GCM"]

    def get_ordered_preference(self) -> list[str]:
        return self.get_allowed_ciphers()

    def set_preferred(self, cipher_name: str):
        idx = self.cmb_preferred.findText(cipher_name)
        if idx >= 0:
            self.cmb_preferred.setCurrentIndex(idx)

    # ── quick selections ──
    def _select_all(self):         self._set_all(True)
    def _clear_all(self):          self._set_all(False)
    def _select_aead_only(self):
        aead = CipherFactory.list_aead_ciphers()
        for i in range(self.lst_ciphers.count()):
            cb = self.lst_ciphers.itemWidget(self.lst_ciphers.item(i))
            if isinstance(cb, QCheckBox):
                cb.setChecked(cb.property("cipher_name") in aead)
    def _select_fastest(self):
        fast = {"AES-128-GCM", "AES-192-GCM", "CHACHA20-POLY1305"}
        for i in range(self.lst_ciphers.count()):
            cb = self.lst_ciphers.itemWidget(self.lst_ciphers.item(i))
            if isinstance(cb, QCheckBox):
                cb.setChecked(cb.property("cipher_name") in fast)
        self.cmb_preferred.setCurrentText("AES-128-GCM")
    def _select_most_secure(self):
        secure = {"AES-256-GCM","CHACHA20-POLY1305","AES-256-CBC","AES-256-CTR","CAMELLIA-256-CBC"}
        for i in range(self.lst_ciphers.count()):
            cb = self.lst_ciphers.itemWidget(self.lst_ciphers.item(i))
            if isinstance(cb, QCheckBox):
                cb.setChecked(cb.property("cipher_name") in secure)
        self.cmb_preferred.setCurrentText("AES-256-GCM")
    def _set_all(self, state: bool):
        for i in range(self.lst_ciphers.count()):
            cb = self.lst_ciphers.itemWidget(self.lst_ciphers.item(i))
            if isinstance(cb, QCheckBox):
                cb.setChecked(state)
        self.cipher_changed.emit()
    def _is_checked(self, name: str) -> bool:
        for i in range(self.lst_ciphers.count()):
            cb = self.lst_ciphers.itemWidget(self.lst_ciphers.item(i))
            if isinstance(cb, QCheckBox) and cb.property("cipher_name") == name:
                return cb.isChecked()
        return False
    def _on_preferred_changed(self, name: str):
        if not name:
            return
        try:
            info = CipherFactory.get_info(name)
            self.lbl_info.setText(
                f"  {info['key_bits']}-bit  "
                f"{'★ AEAD' if info['aead'] else '⚙ HMAC'}  "
                f"{info['speed']}"
            )
        except ValueError:
            self.lbl_info.setText("")
        self.cipher_changed.emit()


# ──────────────────────────────────────────────────────────────────────────────
# Tab 1 — Dashboard
# ──────────────────────────────────────────────────────────────────────────────

class DashboardTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        inner = QWidget()
        self._build_ui(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))

    def _build_ui(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        header = QLabel(f"⚡ {Settings.APP_NAME}")
        header.setFont(HEADER_FONT)
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("color:#cba6f7; letter-spacing:2px;")
        layout.addWidget(header)

        version_lbl = QLabel(f"v{Settings.APP_VERSION}  ·  End-to-end encrypted traffic protection  ·  Multi-cipher")
        version_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version_lbl.setStyleSheet("color:#6c7086; font-size:12px; margin-bottom:8px;")
        layout.addWidget(version_lbl)

        # Status cards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)
        self.card_tunnel   = self._make_card("🖧 Tunnel",    "● Stopped", "#f38ba8")
        self.card_proxy    = self._make_card("🔀 Proxy",     "● Stopped", "#f38ba8")
        self.card_sessions = self._make_card("👥 Sessions",  "0",         "#89b4fa")
        self.card_cipher   = self._make_card("🔒 Cipher",    "—",         "#a6e3a1")
        self.card_keys     = self._make_card("🗝 Keys",      "—",         "#f9e2af")
        for c in (self.card_tunnel, self.card_proxy,
                  self.card_sessions, self.card_cipher, self.card_keys):
            cards_layout.addWidget(c)
        layout.addLayout(cards_layout)

        # System info
        info_group = QGroupBox("System Information")
        info_layout = QFormLayout(info_group)
        info_layout.setSpacing(8)
        info_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.lbl_tunnel_addr   = QLabel("—")
        self.lbl_proxy_addr    = QLabel("—")
        self.lbl_tunnel_cipher = QLabel("—")
        self.lbl_proxy_cipher  = QLabel("—")
        self.lbl_cipher_type   = QLabel("—")
        self.lbl_uptime        = QLabel("—")
        for row_label, widget in [
            ("Tunnel Address:",  self.lbl_tunnel_addr),
            ("Proxy Address:",   self.lbl_proxy_addr),
            ("Tunnel Cipher:",   self.lbl_tunnel_cipher),
            ("Proxy Encryption:",self.lbl_proxy_cipher),
            ("Auth Method:",     self.lbl_cipher_type),
            ("Uptime:",          self.lbl_uptime),
        ]:
            info_layout.addRow(row_label, widget)
        layout.addWidget(info_group)

        # Available ciphers
        cipher_group = QGroupBox(f"Available Ciphers  ({len(CipherFactory.list_ciphers())} registered)")
        cipher_layout = QVBoxLayout(cipher_group)
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["Name", "Key Bits", "Auth", "Speed"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        for info in CipherFactory.get_all_info():
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(info["name"]))
            table.setItem(row, 1, QTableWidgetItem(f"{info['key_bits']}-bit"))
            auth = "★ AEAD" if info["aead"] else "⚙ HMAC-SHA256"
            table.setItem(row, 2, QTableWidgetItem(auth))
            table.setItem(row, 3, QTableWidgetItem(info["speed"]))
        table.setMinimumHeight(min(len(CipherFactory.list_ciphers()) * 30 + 30, 320))
        cipher_layout.addWidget(table)
        layout.addWidget(cipher_group)
        layout.addStretch()

    def _make_card(self, title: str, value: str, colour: str) -> QGroupBox:
        card = QGroupBox(title)
        card.setMinimumHeight(90)
        vl = QVBoxLayout(card)
        vl.setContentsMargins(8, 8, 8, 8)
        lbl = QLabel(value)
        lbl.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(f"color:{colour};")
        lbl.setObjectName("card_value")
        vl.addWidget(lbl)
        return card

    def _card_value(self, card: QGroupBox) -> QLabel:
        return card.findChild(QLabel, "card_value")

    def update_status(self, tunnel_running, proxy_running, session_count,
                      key_count, start_time, active_cipher="—",
                      cipher_details=None):
        tv = self._card_value(self.card_tunnel)
        tv.setText("● Running" if tunnel_running else "● Stopped")
        tv.setStyleSheet(f"color:{'#a6e3a1' if tunnel_running else '#f38ba8'};")

        pv = self._card_value(self.card_proxy)
        pv.setText("● Running" if proxy_running else "● Stopped")
        pv.setStyleSheet(f"color:{'#a6e3a1' if proxy_running else '#f38ba8'};")

        self._card_value(self.card_sessions).setText(str(session_count))
        self._card_value(self.card_cipher).setText(active_cipher)
        self._card_value(self.card_keys).setText(str(key_count))

        self.lbl_tunnel_addr.setText(
            f"{Settings.TUNNEL_HOST}:{Settings.TUNNEL_PORT}" if tunnel_running else "—"
        )
        self.lbl_proxy_addr.setText(
            f"{Settings.PROXY_HOST}:{Settings.PROXY_PORT}" if proxy_running else "—"
        )
        self.lbl_tunnel_cipher.setText(active_cipher)
        if cipher_details:
            auth = cipher_details.get("auth_method", "—")
            self.lbl_cipher_type.setText(auth)
            self.lbl_proxy_cipher.setText(f"✔ {active_cipher}  ({auth})")
        else:
            self.lbl_proxy_cipher.setText("— No tunnel")
            self.lbl_cipher_type.setText("—")

        elapsed = int(time.time() - start_time)
        h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
        self.lbl_uptime.setText(f"{h:02d}:{m:02d}:{s:02d}")


# ──────────────────────────────────────────────────────────────────────────────
# Tab 2 — Tunnel Server
# ──────────────────────────────────────────────────────────────────────────────

class TunnelServerTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.tunnel_server: TunnelServer | None = None
        self.session_manager = SessionManager(timeout=Settings.SESSION_TIMEOUT)
        inner = QWidget()
        self._build_ui(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))

    def _build_ui(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        layout.addWidget(section_label("⚙ Server Configuration"))

        config_group = QGroupBox()
        config_layout = QGridLayout(config_group)
        config_layout.setSpacing(10)

        for col, text in enumerate(["Bind Host", "Bind Port", "Server ID", "Forward Host", "Forward Port"]):
            lbl = QLabel(text)
            lbl.setStyleSheet("color:#a6adc8; font-size:11px;")
            config_layout.addWidget(lbl, 0, col)

        self.txt_host      = QLineEdit(Settings.TUNNEL_HOST)
        self.spn_port      = QSpinBox(); self.spn_port.setRange(1,65535); self.spn_port.setValue(Settings.TUNNEL_PORT)
        self.txt_server_id = QLineEdit("securecrypt-server")
        self.txt_fwd_host  = QLineEdit(); self.txt_fwd_host.setPlaceholderText("Optional")
        self.spn_fwd_port  = QSpinBox(); self.spn_fwd_port.setRange(0,65535)

        for col, w in enumerate([self.txt_host, self.spn_port, self.txt_server_id,
                                  self.txt_fwd_host, self.spn_fwd_port]):
            config_layout.addWidget(w, 1, col)
        layout.addWidget(config_group)

        layout.addWidget(section_label("🔒 Cipher Policy"))
        self.cipher_selector = CipherSelectorWidget("Allowed Ciphers (server preference order)")
        layout.addWidget(self.cipher_selector)

        layout.addWidget(section_label("▶ Controls"))
        btn_layout = QHBoxLayout()
        self.btn_start = QPushButton("▶  Start Server"); self.btn_start.setProperty("role","primary")
        self.btn_stop  = QPushButton("■  Stop Server");  self.btn_stop.setProperty("role","danger"); self.btn_stop.setEnabled(False)
        self.btn_refresh       = QPushButton("⟳  Refresh Sessions")
        self.btn_update_ciphers = QPushButton("↺  Update Ciphers Live"); self.btn_update_ciphers.setEnabled(False)
        self.btn_start.clicked.connect(self.start_server)
        self.btn_stop.clicked.connect(self.stop_server)
        self.btn_refresh.clicked.connect(self.refresh_sessions)
        self.btn_update_ciphers.clicked.connect(self._update_ciphers_live)
        for b in (self.btn_start, self.btn_stop, self.btn_refresh, self.btn_update_ciphers):
            btn_layout.addWidget(b)
        layout.addLayout(btn_layout)

        layout.addWidget(section_label("👥 Active Sessions"))
        self.tbl_sessions = QTableWidget(0, 8)
        self.tbl_sessions.setHorizontalHeaderLabels([
            "Session ID","Peer","Cipher","AEAD","Created","Last Activity","Sent","Received"
        ])
        self.tbl_sessions.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl_sessions.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_sessions.setAlternatingRowColors(True)
        self.tbl_sessions.setMinimumHeight(220)
        layout.addWidget(self.tbl_sessions)
        layout.addStretch()

        self.bridge.session_created.connect(lambda _: self.refresh_sessions())
        self.bridge.session_closed.connect(lambda _:  self.refresh_sessions())

    def start_server(self):
        try:
            fwd_host = self.txt_fwd_host.text().strip() or None
            fwd_port = self.spn_fwd_port.value() or None
            allowed  = self.cipher_selector.get_allowed_ciphers()
            self.tunnel_server = TunnelServer(
                host=self.txt_host.text().strip(),
                port=self.spn_port.value(),
                forward_host=fwd_host, forward_port=fwd_port,
                session_manager=self.session_manager,
                server_id=self.txt_server_id.text().strip(),
                allowed_ciphers=allowed,
                on_session_created=lambda s: self.bridge.session_created.emit(s.info()),
                on_session_closed=lambda sid: self.bridge.session_closed.emit(sid),
                on_data_received=lambda sid, d: self.bridge.data_received.emit(sid, len(d)),
            )
            self.tunnel_server.start()
            self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)
            self.btn_update_ciphers.setEnabled(True)
            self.txt_host.setEnabled(False);  self.spn_port.setEnabled(False)
            self.bridge.status_update.emit(f"Tunnel started — ciphers: {', '.join(allowed[:3])}…")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def stop_server(self):
        if self.tunnel_server:
            self.tunnel_server.stop(); self.tunnel_server = None
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        self.btn_update_ciphers.setEnabled(False)
        self.txt_host.setEnabled(True);  self.spn_port.setEnabled(True)
        self.tbl_sessions.setRowCount(0)
        self.bridge.status_update.emit("Tunnel server stopped")

    def _update_ciphers_live(self):
        if not self.tunnel_server: return
        try:
            new_ciphers = self.cipher_selector.get_allowed_ciphers()
            self.tunnel_server.update_allowed_ciphers(new_ciphers)
            self.bridge.status_update.emit(f"Ciphers updated: {', '.join(new_ciphers[:3])}…")
        except Exception as exc:
            QMessageBox.warning(self, "Error", str(exc))

    def refresh_sessions(self):
        infos = self.session_manager.all_info()
        self.tbl_sessions.setRowCount(len(infos))
        for row, info in enumerate(infos):
            self.tbl_sessions.setItem(row, 0, QTableWidgetItem(info["session_id"][:16]+"…"))
            self.tbl_sessions.setItem(row, 1, QTableWidgetItem(info["peer"]))
            self.tbl_sessions.setItem(row, 2, QTableWidgetItem(info["cipher"]))
            d = info.get("cipher_details", {})
            self.tbl_sessions.setItem(row, 3, QTableWidgetItem("★ Yes" if d.get("aead") else "⚙ HMAC"))
            self.tbl_sessions.setItem(row, 4, QTableWidgetItem(datetime.fromtimestamp(info["created"]).strftime("%H:%M:%S")))
            self.tbl_sessions.setItem(row, 5, QTableWidgetItem(datetime.fromtimestamp(info["last_activity"]).strftime("%H:%M:%S")))
            self.tbl_sessions.setItem(row, 6, QTableWidgetItem(_fmt_bytes(info["bytes_sent"])))
            self.tbl_sessions.setItem(row, 7, QTableWidgetItem(_fmt_bytes(info["bytes_received"])))

    @property
    def is_running(self) -> bool:
        return self.tunnel_server is not None and self.tunnel_server.is_running


# ──────────────────────────────────────────────────────────────────────────────
# Tab 3 — Tunnel Client
# ──────────────────────────────────────────────────────────────────────────────

class TunnelClientTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.tunnel_client: TunnelClient | None = None
        inner = QWidget()
        self._build_ui(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))

    def _build_ui(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        layout.addWidget(section_label("🌐 Remote Tunnel Server"))
        conn_group = QGroupBox()
        conn_layout = QGridLayout(conn_group)
        conn_layout.setSpacing(10)

        for col, text in enumerate(["Remote Host","Remote Port","Local Listen Host","Local Listen Port"]):
            lbl = QLabel(text); lbl.setStyleSheet("color:#a6adc8; font-size:11px;")
            conn_layout.addWidget(lbl, 0, col)

        self.txt_remote_host = QLineEdit("127.0.0.1")
        self.spn_remote_port = QSpinBox(); self.spn_remote_port.setRange(1,65535); self.spn_remote_port.setValue(Settings.TUNNEL_PORT)
        self.txt_local_host  = QLineEdit("127.0.0.1"); self.txt_local_host.setPlaceholderText("Optional")
        self.spn_local_port  = QSpinBox(); self.spn_local_port.setRange(0,65535)

        for col, w in enumerate([self.txt_remote_host, self.spn_remote_port,
                                  self.txt_local_host,  self.spn_local_port]):
            conn_layout.addWidget(w, 1, col)
        layout.addWidget(conn_group)

        layout.addWidget(section_label("🔒 Cipher Preference"))
        self.cipher_selector = CipherSelectorWidget("Preferred Ciphers (client sends to server)")
        layout.addWidget(self.cipher_selector)

        layout.addWidget(section_label("▶ Controls"))
        btn_layout = QHBoxLayout()
        self.btn_connect    = QPushButton("⚡ Connect");    self.btn_connect.setProperty("role","primary")
        self.btn_disconnect = QPushButton("✖ Disconnect"); self.btn_disconnect.setProperty("role","danger"); self.btn_disconnect.setEnabled(False)
        self.btn_connect.clicked.connect(self.connect_tunnel)
        self.btn_disconnect.clicked.connect(self.disconnect_tunnel)
        btn_layout.addWidget(self.btn_connect); btn_layout.addWidget(self.btn_disconnect); btn_layout.addStretch()
        layout.addLayout(btn_layout)

        layout.addWidget(section_label("📊 Session Info"))
        info_group = QGroupBox()
        info_layout = QFormLayout(info_group)
        info_layout.setSpacing(8)
        self.lbl_status       = QLabel("● Disconnected"); self.lbl_status.setStyleSheet("color:#f38ba8;")
        self.lbl_sess_id      = QLabel("—")
        self.lbl_cipher       = QLabel("—")
        self.lbl_cipher_detail= QLabel("—")
        self.lbl_sent         = QLabel("0 B")
        self.lbl_recv         = QLabel("0 B")
        for row_label, w in [
            ("Status:", self.lbl_status), ("Session ID:", self.lbl_sess_id),
            ("Cipher:",  self.lbl_cipher), ("Details:", self.lbl_cipher_detail),
            ("Sent:",    self.lbl_sent),   ("Received:", self.lbl_recv),
        ]:
            info_layout.addRow(row_label, w)
        layout.addWidget(info_group)

        layout.addWidget(section_label("📤 Send Test Data"))
        test_group = QGroupBox()
        test_layout = QHBoxLayout(test_group)
        self.txt_test_msg = QLineEdit(); self.txt_test_msg.setPlaceholderText("Type a message to send encrypted…")
        self.btn_send = QPushButton("Send"); self.btn_send.setEnabled(False)
        self.btn_send.clicked.connect(self.send_test)
        test_layout.addWidget(self.txt_test_msg); test_layout.addWidget(self.btn_send)
        layout.addWidget(test_group)
        layout.addStretch()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_info)
        self._timer.start(1000)

    def connect_tunnel(self):
        def _do():
            try:
                local_host = self.txt_local_host.text().strip() or None
                local_port = self.spn_local_port.value() or None
                preferred  = self.cipher_selector.get_ordered_preference()
                self.tunnel_client = TunnelClient(
                    remote_host=self.txt_remote_host.text().strip(),
                    remote_port=self.spn_remote_port.value(),
                    local_listen_host=local_host,
                    local_listen_port=local_port,
                    preferred_ciphers=preferred,
                    on_session_created=lambda s: self.bridge.session_created.emit(s.info()),
                    on_session_closed=lambda sid: self.bridge.session_closed.emit(sid),
                )
                self.tunnel_client.connect()
                if local_host and local_port:
                    self.tunnel_client.start_local_listener()
                self.tunnel_client.start_keepalive()
                self.bridge.status_update.emit(f"Connected — cipher: {self.tunnel_client.negotiated_cipher}")
            except Exception as exc:
                self.bridge.status_update.emit(f"Connect failed: {exc}")
        self.btn_connect.setEnabled(False)
        threading.Thread(target=_do, daemon=True).start()

    def disconnect_tunnel(self):
        if self.tunnel_client:
            self.tunnel_client.disconnect(); self.tunnel_client = None
        self.btn_connect.setEnabled(True); self.btn_disconnect.setEnabled(False)
        self.btn_send.setEnabled(False)
        self.lbl_status.setText("● Disconnected"); self.lbl_status.setStyleSheet("color:#f38ba8;")
        for w in (self.lbl_sess_id, self.lbl_cipher, self.lbl_cipher_detail):
            w.setText("—")
        self.bridge.status_update.emit("Disconnected")

    def send_test(self):
        msg = self.txt_test_msg.text().strip()
        if not msg or not self.tunnel_client: return
        try:
            self.tunnel_client.send(msg.encode("utf-8"))
            self.txt_test_msg.clear()
            self.bridge.status_update.emit(f"Sent {len(msg)} bytes via {self.tunnel_client.negotiated_cipher}")
        except Exception as exc:
            QMessageBox.warning(self, "Send Error", str(exc))

    def _refresh_info(self):
        if self.tunnel_client and self.tunnel_client.is_connected:
            self.btn_connect.setEnabled(False); self.btn_disconnect.setEnabled(True); self.btn_send.setEnabled(True)
            self.lbl_status.setText("● Connected"); self.lbl_status.setStyleSheet("color:#a6e3a1;")
            info = self.tunnel_client.session_info
            if info:
                self.lbl_sess_id.setText(info["session_id"][:16]+"…")
                self.lbl_cipher.setText(f"🔒 {info['cipher']}")
                d = info.get("cipher_details",{})
                self.lbl_cipher_detail.setText(
                    f"{d.get('key_bits','?')}-bit  ·  {d.get('auth_method','?')}  ·  "
                    f"AEAD: {'Yes' if d.get('aead') else 'No'}"
                )
                self.lbl_sent.setText(_fmt_bytes(info["bytes_sent"]))
                self.lbl_recv.setText(_fmt_bytes(info["bytes_received"]))
        else:
            if not self.btn_connect.isEnabled():
                self.btn_connect.setEnabled(True); self.btn_disconnect.setEnabled(False); self.btn_send.setEnabled(False)

    @property
    def active_cipher(self) -> str | None:
        if self.tunnel_client and self.tunnel_client.is_connected:
            return self.tunnel_client.negotiated_cipher
        return None

    @property
    def active_session(self) -> Session | None:
        if self.tunnel_client and self.tunnel_client.is_connected:
            return self.tunnel_client._session
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Tab 4 — Proxy
# ──────────────────────────────────────────────────────────────────────────────

class ProxyTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.proxy_server: ProxyServer | None = None
        self.logger = logging.getLogger("SecureCrypt.ProxyTab")
        inner = QWidget()
        self._build_ui(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))

    def _build_ui(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        layout.addWidget(section_label("⚙ Proxy Configuration"))
        config_group = QGroupBox()
        config_layout = QGridLayout(config_group)
        for col, text in enumerate(["Listen Host", "Listen Port"]):
            lbl = QLabel(text); lbl.setStyleSheet("color:#a6adc8; font-size:11px;")
            config_layout.addWidget(lbl, 0, col)
        self.txt_host = QLineEdit(Settings.PROXY_HOST)
        self.spn_port = QSpinBox(); self.spn_port.setRange(1,65535); self.spn_port.setValue(Settings.PROXY_PORT)
        config_layout.addWidget(self.txt_host, 1, 0); config_layout.addWidget(self.spn_port, 1, 1)
        layout.addWidget(config_group)

        layout.addWidget(section_label("▶ Controls"))
        btn_layout = QHBoxLayout()
        self.btn_start    = QPushButton("▶ Start Proxy");       self.btn_start.setProperty("role","primary")
        self.btn_stop     = QPushButton("■ Stop Proxy");        self.btn_stop.setProperty("role","danger"); self.btn_stop.setEnabled(False)
        self.btn_attach   = QPushButton("🔗 Attach Tunnel")
        self.btn_detach   = QPushButton("✂ Detach (Direct)")
        self.btn_sys_proxy  = QPushButton("🌐 Set System Proxy")
        self.btn_unset_proxy= QPushButton("🚫 Unset");          self.btn_unset_proxy.setProperty("role","danger")
        self.btn_start.clicked.connect(self.start_proxy)
        self.btn_stop.clicked.connect(self.stop_proxy)
        self.btn_attach.clicked.connect(self._attach_tunnel)
        self.btn_detach.clicked.connect(self._detach_tunnel)
        self.btn_sys_proxy.clicked.connect(self._set_system_proxy)
        self.btn_unset_proxy.clicked.connect(self._unset_system_proxy)
        for b in (self.btn_start, self.btn_stop, self.btn_attach,
                  self.btn_detach, self.btn_sys_proxy, self.btn_unset_proxy):
            btn_layout.addWidget(b)
        layout.addLayout(btn_layout)

        layout.addWidget(section_label("🔒 Encryption Status"))
        enc_group = QGroupBox()
        enc_layout = QFormLayout(enc_group)
        enc_layout.setSpacing(8)
        self.lbl_status      = QLabel("● Stopped"); self.lbl_status.setStyleSheet("color:#f38ba8;")
        self.lbl_mode        = QLabel("—")
        self.lbl_cipher      = QLabel("— No encryption (direct)")
        self.lbl_cipher_bits = QLabel("—")
        self.lbl_cipher_aead = QLabel("—")
        self.lbl_requests    = QLabel("0")
        self.lbl_active      = QLabel("0")
        self.lbl_blocked     = QLabel("0")
        self.lbl_pac         = QLabel("—")
        for row_label, w in [
            ("Status:", self.lbl_status), ("Mode:", self.lbl_mode),
            ("Cipher:", self.lbl_cipher), ("Key Strength:", self.lbl_cipher_bits),
            ("Authentication:", self.lbl_cipher_aead), ("Total Requests:", self.lbl_requests),
            ("Active Connections:", self.lbl_active), ("Blocked:", self.lbl_blocked),
            ("PAC File:", self.lbl_pac),
        ]:
            enc_layout.addRow(row_label, w)
        layout.addWidget(enc_group)

        layout.addWidget(section_label("🚫 Domain Blocking"))
        block_group = QGroupBox()
        block_layout = QHBoxLayout(block_group)
        self.txt_block = QLineEdit(); self.txt_block.setPlaceholderText("e.g. ads.example.com")
        self.btn_block   = QPushButton("Block");   self.btn_block.setProperty("role","danger")
        self.btn_unblock = QPushButton("Unblock"); self.btn_unblock.setProperty("role","success")
        self.btn_block.clicked.connect(self._block_domain)
        self.btn_unblock.clicked.connect(self._unblock_domain)
        block_layout.addWidget(self.txt_block); block_layout.addWidget(self.btn_block); block_layout.addWidget(self.btn_unblock)
        layout.addWidget(block_group)

        layout.addWidget(section_label("📋 Live Request Log"))
        self.txt_log = QPlainTextEdit(); self.txt_log.setReadOnly(True)
        self.txt_log.setMaximumBlockCount(500); self.txt_log.setMinimumHeight(160)
        layout.addWidget(self.txt_log)

        layout.addWidget(section_label("🌐 Browser Setup"))
        self.txt_instructions = QPlainTextEdit(); self.txt_instructions.setReadOnly(True)
        self.txt_instructions.setMinimumHeight(120)
        self.txt_instructions.setPlainText(
            SystemProxyConfig.get_manual_instructions(Settings.PROXY_HOST, Settings.PROXY_PORT)
        )
        layout.addWidget(self.txt_instructions)
        layout.addStretch()

        self.bridge.proxy_request.connect(self._on_proxy_request)
        self._timer = QTimer(self); self._timer.timeout.connect(self._refresh_stats); self._timer.start(1000)

    def start_proxy(self):
        try:
            self.proxy_server = ProxyServer(
                host=self.txt_host.text().strip(),
                port=self.spn_port.value(),
                on_request=lambda m, h, p: self.bridge.proxy_request.emit(m, h, p),
            )
            self.proxy_server.start()
            self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)
            self.txt_host.setEnabled(False); self.spn_port.setEnabled(False)
            self.lbl_status.setText("● Running"); self.lbl_status.setStyleSheet("color:#a6e3a1;")
            self.lbl_pac.setText(f"http://{self.txt_host.text()}:{self.spn_port.value()}/proxy.pac")
            self.bridge.status_update.emit(f"Proxy started on {self.txt_host.text()}:{self.spn_port.value()}")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def stop_proxy(self):
        if self.proxy_server: self.proxy_server.stop(); self.proxy_server = None
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        self.txt_host.setEnabled(True); self.spn_port.setEnabled(True)
        self.lbl_status.setText("● Stopped"); self.lbl_status.setStyleSheet("color:#f38ba8;")
        self.lbl_pac.setText("—"); self.lbl_cipher.setText("— No encryption")
        self.bridge.status_update.emit("Proxy stopped")

    def _attach_tunnel(self):
        main_win = self.window()
        if hasattr(main_win, "tab_tunnel_client"):
            session = main_win.tab_tunnel_client.active_session
            cipher  = main_win.tab_tunnel_client.active_cipher
            if session and session.active:
                self.attach_tunnel_session(session)
                self.bridge.status_update.emit(f"Proxy attached to tunnel — cipher: {cipher}")
            else:
                QMessageBox.warning(self, "No Tunnel", "Connect to a tunnel server first (Tunnel Client tab).")

    def _detach_tunnel(self):
        self.attach_tunnel_session(None)
        self.bridge.status_update.emit("Proxy detached — direct mode")

    def attach_tunnel_session(self, session: Session | None):
        if self.proxy_server:
            self.proxy_server.tunnel_session = session

    def _set_system_proxy(self):
        success, msg = SystemProxyConfig.enable_system_proxy(self.txt_host.text().strip(), self.spn_port.value())
        QMessageBox.information(self, "System Proxy", f"{'✔' if success else '✖'} {msg}")
        self.bridge.status_update.emit(msg)

    def _unset_system_proxy(self):
        success, msg = SystemProxyConfig.disable_system_proxy()
        QMessageBox.information(self, "System Proxy", msg)
        self.bridge.status_update.emit(msg)

    def _block_domain(self):
        domain = self.txt_block.text().strip()
        if domain and self.proxy_server:
            self.proxy_server.add_blocked_domain(domain); self.txt_block.clear()
            self.bridge.status_update.emit(f"Blocked: {domain}")

    def _unblock_domain(self):
        domain = self.txt_block.text().strip()
        if domain and self.proxy_server:
            self.proxy_server.remove_blocked_domain(domain); self.txt_block.clear()
            self.bridge.status_update.emit(f"Unblocked: {domain}")

    def _on_proxy_request(self, method: str, host: str, port: int):
        ts = datetime.now().strftime("%H:%M:%S")
        encrypted = "🔒" if (self.proxy_server and self.proxy_server.tunnel_session
                              and self.proxy_server.tunnel_session.active) else "⚠"
        cipher_tag = ""
        if self.proxy_server and self.proxy_server.tunnel_session:
            cipher_tag = f" [{self.proxy_server.tunnel_session.cipher}]"
        self.txt_log.appendPlainText(f"[{ts}] {encrypted} {method:8s} {host}:{port}{cipher_tag}")

    def _refresh_stats(self):
        if self.proxy_server and self.proxy_server.is_running:
            s = self.proxy_server.stats()
            self.lbl_requests.setText(str(s["total_requests"]))
            self.lbl_active.setText(str(s["active_connections"]))
            self.lbl_blocked.setText(str(s["blocked_requests"]))
            self.lbl_mode.setText(s["mode"])
            if s["tunnel_active"]:
                cipher  = s.get("tunnel_cipher","Unknown")
                details = s.get("tunnel_cipher_info",{})
                self.lbl_cipher.setText(f"🔒 {cipher}")
                self.lbl_cipher_bits.setText(f"{details.get('key_bits','?')}-bit")
                self.lbl_cipher_aead.setText("★ Built-in (AEAD)" if details.get("aead") else "⚙ HMAC-SHA256")
            else:
                self.lbl_cipher.setText("— No encryption (direct)")
                self.lbl_cipher_bits.setText("—"); self.lbl_cipher_aead.setText("—")

    @property
    def is_running(self) -> bool:
        return self.proxy_server is not None and self.proxy_server.is_running

    @property
    def active_cipher(self) -> str | None:
        if self.proxy_server and self.proxy_server.tunnel_session and self.proxy_server.tunnel_session.active:
            return self.proxy_server.tunnel_session.cipher
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Tab 5 — E2E Messaging
# ──────────────────────────────────────────────────────────────────────────────

class E2EMessagingTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.peer_client:  PeerClient   | None = None
        self.relay_server: RelayServer  | None = None
        self._peer_list: list[dict] = []
        self._peer_refresh_timer = QTimer(self)
        self._peer_refresh_timer.timeout.connect(self._refresh_peers)

        # Chat + file panel uses a splitter — not a scroll area — so text areas grow naturally
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        # Top controls in scroll area, bottom chat in splitter
        top_widget = QWidget()
        self._build_top(top_widget)
        top_scroll = make_scroll(top_widget)
        top_scroll.setMaximumHeight(520)

        bottom = QWidget()
        self._build_bottom(bottom)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(top_scroll)
        splitter.addWidget(bottom)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([480, 400])
        outer.addWidget(splitter)

    def _build_top(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 16, 20, 8)

        # LAN IP banner
        local_ip = _get_local_ip()
        ip_banner = QGroupBox("📡 Your LAN IP — share with the other laptop")
        ip_banner.setStyleSheet("QGroupBox { border:1px solid #a6e3a1; color:#a6e3a1; }")
        ip_layout = QHBoxLayout(ip_banner)
        self.lbl_local_ip = QLabel(f"  {local_ip}  ")
        self.lbl_local_ip.setFont(QFont("Cascadia Code", 16, QFont.Weight.Bold))
        self.lbl_local_ip.setStyleSheet("color:#a6e3a1; background:#1e3a2e; border-radius:6px; padding:4px 14px;")
        ip_layout.addWidget(self.lbl_local_ip)
        btn_copy = QPushButton("📋 Copy IP"); btn_copy.setFixedWidth(110)
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(local_ip))
        ip_layout.addWidget(btn_copy)
        ip_layout.addStretch()
        hint = QLabel("<b>Laptop A:</b> Start Relay → Connect  |  <b>Laptop B:</b> Enter A's IP → Connect → Refresh → E2E Session")
        hint.setStyleSheet("color:#cba6f7; font-size:11px; padding:0 8px;")
        ip_layout.addWidget(hint)
        layout.addWidget(ip_banner)

        # Connection
        layout.addWidget(section_label("🔗 Relay Connection"))
        conn_group = QGroupBox()
        conn_layout = QGridLayout(conn_group)
        conn_layout.setSpacing(10)

        for col, text in enumerate(["Username","Relay Host","Relay Port"]):
            lbl = QLabel(text); lbl.setStyleSheet("color:#a6adc8; font-size:11px;")
            conn_layout.addWidget(lbl, 0, col)

        self.txt_username   = QLineEdit("alice")
        self.txt_relay_host = QLineEdit("127.0.0.1"); self.txt_relay_host.setPlaceholderText("Laptop A's IP e.g. 192.168.1.10")
        self.spn_relay_port = QSpinBox(); self.spn_relay_port.setRange(1,65535); self.spn_relay_port.setValue(9091)

        for col, w in enumerate([self.txt_username, self.txt_relay_host, self.spn_relay_port]):
            conn_layout.addWidget(w, 1, col)

        btn_row = QHBoxLayout()
        self.btn_start_relay = QPushButton("▶ Start Relay"); self.btn_start_relay.setProperty("role","success")
        self.btn_connect     = QPushButton("⚡ Connect & Register"); self.btn_connect.setProperty("role","primary")
        self.btn_disconnect  = QPushButton("✖ Disconnect"); self.btn_disconnect.setProperty("role","danger"); self.btn_disconnect.setEnabled(False)
        self.btn_start_relay.setToolTip("Run on ONE laptop only — others connect to it")
        self.btn_start_relay.clicked.connect(self._start_relay)
        self.btn_connect.clicked.connect(self._connect)
        self.btn_disconnect.clicked.connect(self._disconnect)
        for b in (self.btn_start_relay, self.btn_connect, self.btn_disconnect):
            btn_row.addWidget(b)
        btn_row.addStretch()
        conn_layout.addLayout(btn_row, 2, 0, 1, 3)

        self.lbl_conn_status = QLabel("● Not connected"); self.lbl_conn_status.setStyleSheet("color:#f38ba8;")
        self.lbl_identity    = QLabel("Identity: Not generated"); self.lbl_identity.setStyleSheet("color:#6c7086;")
        conn_layout.addWidget(self.lbl_conn_status, 3, 0, 1, 3)
        conn_layout.addWidget(self.lbl_identity,    4, 0, 1, 3)
        layout.addWidget(conn_group)

        # Peers & E2E
        layout.addWidget(section_label("👥 Peers & E2E Sessions"))
        peer_group = QGroupBox()
        peer_layout = QHBoxLayout(peer_group)
        peer_layout.setSpacing(14)

        peer_left = QVBoxLayout()
        self.lbl_peer_count = QLabel("Online Peers: (not connected)"); self.lbl_peer_count.setStyleSheet("color:#6c7086; font-size:11px;")
        peer_left.addWidget(self.lbl_peer_count)
        self.lst_peers = QListWidget(); self.lst_peers.setMinimumHeight(130)
        self.lst_peers.itemDoubleClicked.connect(self._on_peer_double_click)
        peer_left.addWidget(self.lst_peers)
        btn_refresh = QPushButton("🔄 Refresh Peers"); btn_refresh.clicked.connect(self._refresh_peers)
        peer_left.addWidget(btn_refresh)
        peer_layout.addLayout(peer_left, 2)

        peer_right = QVBoxLayout()
        peer_right.addWidget(QLabel("Cipher:"))
        self.cmb_e2e_cipher = QComboBox(); self.cmb_e2e_cipher.addItems(CipherFactory.list_ciphers())
        peer_right.addWidget(self.cmb_e2e_cipher)
        self.btn_init_e2e = QPushButton("🔐 Establish E2E Session"); self.btn_init_e2e.setProperty("role","primary")
        self.btn_init_e2e.clicked.connect(self._init_e2e)
        peer_right.addWidget(self.btn_init_e2e)
        self.lbl_session = QLabel("No active E2E session"); self.lbl_session.setStyleSheet("color:#f9e2af;"); self.lbl_session.setWordWrap(True)
        peer_right.addWidget(self.lbl_session)
        peer_layout.addLayout(peer_right, 1)
        layout.addWidget(peer_group)

        # Security info
        layout.addWidget(section_label("🔒 Security Verification"))
        self.txt_security = QPlainTextEdit(); self.txt_security.setReadOnly(True); self.txt_security.setMinimumHeight(70)
        self.txt_security.setPlaceholderText("Your RSA fingerprint appears here after connecting.\nShare with peer to verify identity (like WhatsApp security code).")
        layout.addWidget(self.txt_security)

    def _build_bottom(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 8, 20, 16)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Chat panel
        chat_widget = QWidget()
        chat_layout = QVBoxLayout(chat_widget)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_layout.addWidget(section_label("💬 Encrypted Chat"))
        self.txt_chat = QPlainTextEdit(); self.txt_chat.setReadOnly(True); self.txt_chat.setMaximumBlockCount(2000)
        chat_layout.addWidget(self.txt_chat)
        msg_row = QHBoxLayout()
        self.txt_msg = QLineEdit(); self.txt_msg.setPlaceholderText("Type a message… (need E2E session first)")
        self.txt_msg.returnPressed.connect(self._send_message)
        self.btn_send_msg = QPushButton("📤 Send"); self.btn_send_msg.setProperty("role","primary")
        self.btn_send_msg.clicked.connect(self._send_message)
        msg_row.addWidget(self.txt_msg); msg_row.addWidget(self.btn_send_msg)
        chat_layout.addLayout(msg_row)
        splitter.addWidget(chat_widget)

        # File panel
        file_widget = QWidget()
        file_layout = QVBoxLayout(file_widget)
        file_layout.setContentsMargins(0, 0, 0, 0)
        file_layout.addWidget(section_label("📁 File Transfer"))
        self.btn_send_file = QPushButton("📤 Send File"); self.btn_send_file.setProperty("role","primary")
        self.btn_send_file.clicked.connect(self._send_file)
        file_layout.addWidget(self.btn_send_file)
        self.progress_file = QProgressBar(); self.progress_file.setValue(0); self.progress_file.setVisible(False)
        file_layout.addWidget(self.progress_file)
        self.lbl_file_status = QLabel("No transfer in progress"); self.lbl_file_status.setWordWrap(True)
        file_layout.addWidget(self.lbl_file_status)
        file_layout.addStretch()
        splitter.addWidget(file_widget)

        splitter.setSizes([650, 250])
        layout.addWidget(splitter)

    # ── Relay ──────────────────────────────────────────────────────────────────

    def _start_relay(self):
        try:
            port = self.spn_relay_port.value()
            self.relay_server = RelayServer("0.0.0.0", port)
            self.relay_server.start()
            self.btn_start_relay.setEnabled(False)
            self.btn_start_relay.setText("✅ Relay Running")
            local_ip = _get_local_ip()
            self.txt_relay_host.setText(local_ip)
            self.bridge.status_update.emit(f"Relay running on {local_ip}:{port} — share IP with other laptop")
            self._chat_system(f"📡 Relay started. Other laptop should connect to: {local_ip}:{port}")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    # ── Connection ─────────────────────────────────────────────────────────────

    def _connect(self):
        username   = self.txt_username.text().strip()
        relay_host = self.txt_relay_host.text().strip()
        relay_port = self.spn_relay_port.value()
        if not username:
            QMessageBox.warning(self, "Error", "Enter a username"); return
        self.lbl_conn_status.setText("● Connecting…"); self.lbl_conn_status.setStyleSheet("color:#f9e2af;")
        def _do():
            self.peer_client = PeerClient(
                username=username, relay_host=relay_host, relay_port=relay_port,
                on_message_received=self._cb_message,
                on_file_started=self._cb_file_start, on_file_progress=self._cb_file_progress,
                on_file_complete=self._cb_file_complete, on_peer_list=self._cb_peers,
                on_e2e_established=self._cb_e2e,
                on_status=lambda m: self.bridge.status_update.emit(m),
                on_error=lambda m: self.bridge.status_update.emit(f"⚠ {m}"),
            )
            if self.peer_client.connect():
                self.lbl_conn_status.setText(f"● Connected as '{username}' → {relay_host}:{relay_port}")
                self.lbl_conn_status.setStyleSheet("color:#a6e3a1;")
                self.bridge.status_update.emit(f"Registered as '{username}' on {relay_host}:{relay_port}")
                QTimer.singleShot(1500, self._update_identity)
                QTimer.singleShot(3000, self._refresh_peers)
                self._peer_refresh_timer.start(10_000)
            else:
                self.lbl_conn_status.setText(f"● Failed — {relay_host}:{relay_port}")
                self.lbl_conn_status.setStyleSheet("color:#f38ba8;")
                self.btn_connect.setEnabled(True); self.btn_disconnect.setEnabled(False)
        threading.Thread(target=_do, daemon=True).start()
        self.btn_connect.setEnabled(False); self.btn_disconnect.setEnabled(True)

    def _update_identity(self):
        if self.peer_client and self.peer_client.identity_info:
            info = self.peer_client.identity_info
            self.lbl_identity.setText(
                f"✅ {info['username']}  |  RSA-{info['key_size']}  |  "
                f"Fingerprint: {info['fingerprint'][:24]}…"
            )
            self.txt_security.setPlainText(
                f"Your fingerprint:\n{info['fingerprint']}\n\n"
                f"Share with your peer to verify identity (like WhatsApp security code)."
            )

    def _disconnect(self):
        self._peer_refresh_timer.stop()
        if self.peer_client: self.peer_client.disconnect(); self.peer_client = None
        if self.relay_server:
            self.relay_server.stop(); self.relay_server = None
            self.btn_start_relay.setEnabled(True); self.btn_start_relay.setText("▶ Start Relay")
        self.btn_connect.setEnabled(True); self.btn_disconnect.setEnabled(False)
        self.lbl_conn_status.setText("● Not connected"); self.lbl_conn_status.setStyleSheet("color:#f38ba8;")
        self.lbl_identity.setText("Identity: Not connected")
        self.lst_peers.clear(); self.lbl_peer_count.setText("Online Peers: (not connected)")
        self.bridge.status_update.emit("Disconnected")

    # ── Peers ──────────────────────────────────────────────────────────────────

    def _refresh_peers(self):
        if self.peer_client and self.peer_client.is_connected:
            self.peer_client.request_peer_list()

    def _cb_peers(self, peers: list[dict]):
        self._peer_list = peers
        self.lst_peers.clear()
        online = [p for p in peers if p.get("online", True)]
        self.lbl_peer_count.setText(f"Online Peers: {len(online)} found")
        for p in peers:
            icon = "🟢" if p.get("online", True) else "🔴"
            self.lst_peers.addItem(f"{icon} {p['username']}")
        if not peers:
            self.lst_peers.addItem("(no peers yet — ask them to connect)")

    def _on_peer_double_click(self, _item):
        self._init_e2e()

    # ── E2E ───────────────────────────────────────────────────────────────────

    def _init_e2e(self):
        if not self.peer_client or not self.peer_client.is_connected:
            QMessageBox.warning(self, "Error", "Connect to relay first"); return
        item = self.lst_peers.currentItem()
        if not item: QMessageBox.warning(self, "Error", "Select a peer"); return
        parts = item.text().split(" ", 1)
        if len(parts) < 2: return
        peer_name = parts[1].strip()
        if not peer_name or peer_name.startswith("("): return
        cipher = self.cmb_e2e_cipher.currentText()
        peer_data = next((p for p in self._peer_list if p["username"] == peer_name), None)
        if not peer_data:
            QMessageBox.warning(self, "Error", f"Peer '{peer_name}' not in list.\nClick 🔄 Refresh first."); return
        if "rsa_public_key" not in peer_data:
            QMessageBox.warning(self, "Error", "Peer public key unavailable.\nRefresh peer list."); return
        self.lbl_session.setText(f"⏳ Establishing E2E with {peer_name}…")
        threading.Thread(
            target=lambda: self.peer_client.initiate_e2e(peer_name, peer_data["rsa_public_key"], cipher),
            daemon=True,
        ).start()

    def _cb_e2e(self, peer_username: str, session_info: dict):
        cipher = session_info.get("cipher","?")
        ci     = session_info.get("cipher_info",{})
        fp     = session_info.get("peer_fingerprint","?")
        self.lbl_session.setText(
            f"✅ E2E with {peer_username}\n"
            f"Cipher: {cipher}  ({ci.get('key_bits','?')}-bit  "
            f"{'AEAD' if ci.get('aead') else 'HMAC'})\n"
            f"Peer fingerprint: {fp[:24]}…"
        )
        self.txt_security.appendPlainText(f"\nPeer '{peer_username}' fingerprint:\n{fp}")
        self._chat_system(f"✅ E2E established with {peer_username}  [{cipher}]")

    # ── Messaging ──────────────────────────────────────────────────────────────

    def _send_message(self):
        if not self.peer_client: return
        text = self.txt_msg.text().strip()
        if not text: return
        item = self.lst_peers.currentItem()
        if not item: QMessageBox.warning(self, "Error", "Select a peer"); return
        parts = item.text().split(" ", 1)
        if len(parts) < 2: return
        peer_name = parts[1].strip()
        threading.Thread(target=lambda: self.peer_client.send_message(peer_name, text), daemon=True).start()
        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_chat.appendPlainText(f"[{ts}] 📤 You → {peer_name}: {text}")
        self.txt_msg.clear()

    def _cb_message(self, from_user: str, text: str, sig_valid: bool, timestamp: float, cipher: str):
        ts = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
        sig_icon = "✅" if sig_valid else "⚠ UNVERIFIED"
        self.txt_chat.appendPlainText(f"[{ts}] 📨 {from_user}: {text}\n         {sig_icon}  🔒 {cipher}")

    # ── File Transfer ──────────────────────────────────────────────────────────

    def _send_file(self):
        if not self.peer_client: return
        item = self.lst_peers.currentItem()
        if not item: QMessageBox.warning(self, "Error", "Select a peer"); return
        parts = item.text().split(" ", 1)
        if len(parts) < 2: return
        peer_name = parts[1].strip()
        filepath, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if not filepath: return

        def _progress(p):
            self.progress_file.setVisible(True)
            self.progress_file.setValue(int(p * 100))
            self.lbl_file_status.setText(f"Sending… {p*100:.0f}%")

        def _do():
            success = self.peer_client.send_file(peer_name, filepath, progress_callback=_progress)
            self.progress_file.setVisible(False)
            if success:
                self._chat_system(f"✅ File sent to {peer_name}: {os.path.basename(filepath)}")

        threading.Thread(target=_do, daemon=True).start()

    def _cb_file_start(self, from_user: str, meta: dict):
        self.progress_file.setVisible(True); self.progress_file.setValue(0)
        self._chat_system(f"📥 Receiving from {from_user}: {meta['filename']} ({FileMetadata.format_size(meta['file_size'])})")

    def _cb_file_progress(self, transfer_id: str, progress: float):
        self.progress_file.setValue(int(progress * 100))
        self.lbl_file_status.setText(f"Receiving… {progress*100:.0f}%")

    def _cb_file_complete(self, from_user: str, result: dict):
        self.progress_file.setVisible(False)
        if result["success"]:
            self._chat_system(f"✅ File from {from_user}: {result['filename']}\n   Hash ✅  Sig ✅  Saved: {result['path']}")
            self.lbl_file_status.setText(f"✅ {result['filename']} received")
        else:
            h = "✅" if result["hash_valid"] else "❌"
            s = "✅" if result["sig_valid"] else "❌"
            self._chat_system(f"❌ File from {from_user}: FAILED  Hash:{h}  Sig:{s}")
            self.lbl_file_status.setText("❌ Verification failed")

    def _chat_system(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_chat.appendPlainText(f"[{ts}] 🔧 {msg}")


# ──────────────────────────────────────────────────────────────────────────────
# Tab 6 — Crypto Tools
# ──────────────────────────────────────────────────────────────────────────────

class CryptoToolsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._aes_key: bytes | None = None
        inner = QWidget()
        self._build_ui(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))

    def _build_ui(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        # AES
        layout.addWidget(section_label("🔐 AES-256-GCM Encrypt / Decrypt"))
        aes_group = QGroupBox()
        aes_layout = QVBoxLayout(aes_group)
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("AES Key (hex):"))
        self.txt_aes_key = QLineEdit(); self.txt_aes_key.setPlaceholderText("Click Generate or paste 64 hex chars")
        key_row.addWidget(self.txt_aes_key)
        btn_gen = QPushButton("⟳ Generate"); btn_gen.setProperty("role","primary"); btn_gen.clicked.connect(self._gen_aes_key)
        key_row.addWidget(btn_gen)
        aes_layout.addLayout(key_row)
        self.txt_plain = QTextEdit(); self.txt_plain.setPlaceholderText("Plaintext…"); self.txt_plain.setMinimumHeight(80)
        aes_layout.addWidget(self.txt_plain)
        enc_dec = QHBoxLayout()
        self.btn_encrypt = QPushButton("🔒 Encrypt"); self.btn_encrypt.setProperty("role","primary"); self.btn_encrypt.clicked.connect(self._encrypt)
        self.btn_decrypt = QPushButton("🔓 Decrypt"); self.btn_decrypt.clicked.connect(self._decrypt)
        enc_dec.addWidget(self.btn_encrypt); enc_dec.addWidget(self.btn_decrypt); enc_dec.addStretch()
        aes_layout.addLayout(enc_dec)
        self.txt_cipher_out = QTextEdit(); self.txt_cipher_out.setPlaceholderText("Ciphertext (hex)…"); self.txt_cipher_out.setMinimumHeight(80)
        aes_layout.addWidget(self.txt_cipher_out)
        layout.addWidget(aes_group)

        # Hash
        layout.addWidget(section_label("# Hash"))
        hash_group = QGroupBox()
        hash_layout = QVBoxLayout(hash_group)
        hash_input_row = QHBoxLayout()
        self.txt_hash_input = QLineEdit(); self.txt_hash_input.setPlaceholderText("Data to hash…")
        self.cmb_hash = QComboBox(); self.cmb_hash.addItems(["SHA-256","SHA-512","BLAKE2b"])
        btn_hash = QPushButton("Hash"); btn_hash.setProperty("role","primary"); btn_hash.clicked.connect(self._hash)
        hash_input_row.addWidget(self.txt_hash_input); hash_input_row.addWidget(self.cmb_hash); hash_input_row.addWidget(btn_hash)
        hash_layout.addLayout(hash_input_row)
        self.txt_hash_output = QLineEdit(); self.txt_hash_output.setReadOnly(True); self.txt_hash_output.setPlaceholderText("Hash output…")
        hash_layout.addWidget(self.txt_hash_output)
        layout.addWidget(hash_group)

        # RSA
        layout.addWidget(section_label("🗝 RSA Quick Test"))
        rsa_group = QGroupBox()
        rsa_layout = QVBoxLayout(rsa_group)
        btn_rsa = QPushButton("⟳ Generate RSA-4096 → Encrypt → Decrypt round-trip"); btn_rsa.clicked.connect(self._rsa_test)
        rsa_layout.addWidget(btn_rsa)
        self.txt_rsa_result = QPlainTextEdit(); self.txt_rsa_result.setReadOnly(True); self.txt_rsa_result.setMinimumHeight(120)
        rsa_layout.addWidget(self.txt_rsa_result)
        layout.addWidget(rsa_group)

        # ECC
        layout.addWidget(section_label("📐 ECC Quick Test"))
        ecc_group = QGroupBox()
        ecc_layout = QVBoxLayout(ecc_group)
        btn_ecc = QPushButton("⟳ ECDH Key Exchange + Sign/Verify round-trip"); btn_ecc.clicked.connect(self._ecc_test)
        ecc_layout.addWidget(btn_ecc)
        self.txt_ecc_result = QPlainTextEdit(); self.txt_ecc_result.setReadOnly(True); self.txt_ecc_result.setMinimumHeight(120)
        ecc_layout.addWidget(self.txt_ecc_result)
        layout.addWidget(ecc_group)
        layout.addStretch()

    def _gen_aes_key(self):
        self._aes_key = SecureRandom.generate_bytes(32)
        self.txt_aes_key.setText(self._aes_key.hex())

    def _get_aes(self) -> AESCrypto | None:
        hex_key = self.txt_aes_key.text().strip()
        if not hex_key: QMessageBox.warning(self,"No Key","Generate or enter an AES key first."); return None
        try:
            key = bytes.fromhex(hex_key)
        except ValueError:
            QMessageBox.warning(self,"Bad Key","Invalid hex key."); return None
        if len(key) not in (16,24,32):
            QMessageBox.warning(self,"Bad Key","Key must be 16, 24 or 32 bytes."); return None
        return AESCrypto(key=key)

    def _encrypt(self):
        aes = self._get_aes()
        if not aes: return
        pt = self.txt_plain.toPlainText().encode("utf-8")
        if not pt: return
        nonce, ct = aes.encrypt_gcm(pt)
        self.txt_cipher_out.setPlainText(f"{nonce.hex()}:{ct.hex()}")

    def _decrypt(self):
        aes = self._get_aes()
        if not aes: return
        raw = self.txt_cipher_out.toPlainText().strip()
        if ":" not in raw: QMessageBox.warning(self,"Format","Expected nonce_hex:ciphertext_hex"); return
        try:
            nonce_hex, ct_hex = raw.split(":",1)
            pt = aes.decrypt_gcm(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex))
            self.txt_plain.setPlainText(pt.decode("utf-8"))
        except Exception as exc:
            QMessageBox.warning(self,"Decrypt Error", str(exc))

    def _hash(self):
        data = self.txt_hash_input.text().encode("utf-8")
        if not data: return
        algo = self.cmb_hash.currentText()
        if algo == "SHA-256":   result = HashCrypto.sha256(data)
        elif algo == "SHA-512": result = HashCrypto.sha512(data)
        else:                   result = HashCrypto.blake2b(data)
        self.txt_hash_output.setText(result.hex())

    def _rsa_test(self):
        self.txt_rsa_result.clear()
        try:
            t0 = time.time()
            rsa = RSACrypto(key_size=4096); rsa.generate_keys()
            t1 = time.time()
            msg = b"Hello from SecureCrypt RSA test!"
            ct = rsa.encrypt(msg); pt = rsa.decrypt(ct)
            sig = rsa.sign(msg); valid = rsa.verify(msg, sig)
            self.txt_rsa_result.appendPlainText(f"Key generation : {t1-t0:.2f}s")
            self.txt_rsa_result.appendPlainText(f"Plaintext      : {msg.decode()}")
            self.txt_rsa_result.appendPlainText(f"Decrypted      : {pt.decode()}")
            self.txt_rsa_result.appendPlainText(f"Match          : {'✅' if pt==msg else '❌'}")
            self.txt_rsa_result.appendPlainText(f"Sig valid      : {'✅' if valid else '❌'}")
        except Exception as exc:
            self.txt_rsa_result.appendPlainText(f"Error: {exc}")

    def _ecc_test(self):
        self.txt_ecc_result.clear()
        try:
            alice = ECCCrypto("SECP384R1"); alice.generate_keys()
            bob   = ECCCrypto("SECP384R1"); bob.generate_keys()
            key_a = alice.derive_shared_key(bob.public_key)
            key_b = bob.derive_shared_key(alice.public_key)
            msg = b"ECDH shared-secret test"
            sig = alice.sign(msg); valid = alice.verify(msg, sig)
            self.txt_ecc_result.appendPlainText(f"Alice shared : {key_a.hex()[:32]}…")
            self.txt_ecc_result.appendPlainText(f"Bob shared   : {key_b.hex()[:32]}…")
            self.txt_ecc_result.appendPlainText(f"Keys match   : {'✅' if key_a==key_b else '❌'}")
            self.txt_ecc_result.appendPlainText(f"ECDSA valid  : {'✅' if valid else '❌'}")
        except Exception as exc:
            self.txt_ecc_result.appendPlainText(f"Error: {exc}")


# ──────────────────────────────────────────────────────────────────────────────
# Tab 7 — Key Manager
# ──────────────────────────────────────────────────────────────────────────────

class KeyManagerTab(QWidget):
    def __init__(self, bridge: SignalBridge, parent=None):
        super().__init__(parent)
        self.bridge = bridge
        self.km = KeyManager()
        inner = QWidget()
        self._build_ui(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))
        self._refresh_list()

    def _build_ui(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        layout.addWidget(section_label("⟳ Generate Key Pair"))
        gen_group = QGroupBox()
        gen_layout = QGridLayout(gen_group)
        gen_layout.setSpacing(10)
        for col, text in enumerate(["Name","Type","Password (optional)"]):
            lbl = QLabel(text); lbl.setStyleSheet("color:#a6adc8; font-size:11px;")
            gen_layout.addWidget(lbl, 0, col)
        self.txt_name = QLineEdit("server")
        self.cmb_type = QComboBox(); self.cmb_type.addItems(["RSA-4096","ECC-P384"])
        self.txt_pass = QLineEdit(); self.txt_pass.setEchoMode(QLineEdit.EchoMode.Password); self.txt_pass.setPlaceholderText("Leave blank for no encryption")
        btn_generate = QPushButton("⟳ Generate"); btn_generate.setProperty("role","primary"); btn_generate.clicked.connect(self._generate)
        gen_layout.addWidget(self.txt_name, 1, 0)
        gen_layout.addWidget(self.cmb_type, 1, 1)
        gen_layout.addWidget(self.txt_pass, 1, 2)
        gen_layout.addWidget(btn_generate,  1, 3)
        layout.addWidget(gen_group)

        layout.addWidget(section_label("🗝 Keys on Disk"))
        self.tbl_keys = QTableWidget(0, 2)
        self.tbl_keys.setHorizontalHeaderLabels(["File Name","Path"])
        self.tbl_keys.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl_keys.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_keys.setAlternatingRowColors(True)
        self.tbl_keys.setMinimumHeight(200)
        layout.addWidget(self.tbl_keys)

        btn_row = QHBoxLayout()
        btn_refresh = QPushButton("⟳ Refresh"); btn_refresh.clicked.connect(self._refresh_list)
        btn_delete  = QPushButton("🗑 Delete Selected"); btn_delete.setProperty("role","danger"); btn_delete.clicked.connect(self._delete_selected)
        btn_row.addWidget(btn_refresh); btn_row.addWidget(btn_delete); btn_row.addStretch()
        layout.addLayout(btn_row)
        layout.addStretch()

    def _generate(self):
        name = self.txt_name.text().strip()
        if not name: QMessageBox.warning(self,"Error","Enter a key name."); return
        pwd   = self.txt_pass.text().encode() if self.txt_pass.text() else None
        ktype = self.cmb_type.currentText()
        try:
            if ktype.startswith("RSA"):
                priv, pub = self.km.generate_rsa_keypair(name, key_size=4096, password=pwd)
            else:
                priv, pub = self.km.generate_ecc_keypair(name, curve="SECP384R1", password=pwd)
            QMessageBox.information(self,"Success",f"Keys generated:\n  {priv}\n  {pub}")
            self._refresh_list()
            self.bridge.status_update.emit(f"{ktype} key pair '{name}' generated")
        except Exception as exc:
            QMessageBox.critical(self,"Error",str(exc))

    def _refresh_list(self):
        keys = self.km.list_keys()
        self.tbl_keys.setRowCount(len(keys))
        for row, fname in enumerate(keys):
            self.tbl_keys.setItem(row, 0, QTableWidgetItem(fname))
            self.tbl_keys.setItem(row, 1, QTableWidgetItem(os.path.join(self.km.keys_dir, fname)))

    def _delete_selected(self):
        row = self.tbl_keys.currentRow()
        if row < 0: QMessageBox.warning(self,"Error","Select a key to delete."); return
        fname = self.tbl_keys.item(row, 0).text()
        reply = QMessageBox.question(self,"Confirm",f"Delete {fname}? This cannot be undone.",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                os.remove(os.path.join(self.km.keys_dir, fname))
                self._refresh_list()
                self.bridge.status_update.emit(f"Deleted {fname}")
            except Exception as exc:
                QMessageBox.critical(self,"Error",str(exc))

    @property
    def key_count(self) -> int:
        return self.tbl_keys.rowCount()


# ──────────────────────────────────────────────────────────────────────────────
# Tab 8 — Logs
# ──────────────────────────────────────────────────────────────────────────────

class LogsTab(QWidget):
    def __init__(self, log_handler: QtLogHandler, parent=None):
        super().__init__(parent)
        self.log_handler = log_handler
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(20, 16, 20, 16)

        layout.addWidget(section_label("📋 Live Log Output"))

        toolbar = QHBoxLayout()
        self.chk_auto = QCheckBox("Auto-scroll"); self.chk_auto.setChecked(True)
        toolbar.addWidget(self.chk_auto)
        btn_clear = QPushButton("🗑 Clear"); btn_clear.clicked.connect(self._clear)
        btn_save  = QPushButton("💾 Save to File"); btn_save.clicked.connect(self._save)
        toolbar.addWidget(btn_clear); toolbar.addWidget(btn_save); toolbar.addStretch()
        layout.addLayout(toolbar)

        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setMaximumBlockCount(5000)
        self.txt_log.setFont(MONO_FONT)
        layout.addWidget(self.txt_log)  # no scroll wrapper — it's a terminal, fills the tab

        self.log_handler.signal_emitter.log_message.connect(self._append_log)

    def _append_log(self, msg: str):
        self.txt_log.appendPlainText(msg)
        if self.chk_auto.isChecked():
            cursor = self.txt_log.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.txt_log.setTextCursor(cursor)

    def _clear(self): self.txt_log.clear()

    def _save(self):
        path, _ = QFileDialog.getSaveFileName(self,"Save Log","securecrypt.log","Log Files (*.log *.txt)")
        if path:
            with open(path,"w") as f:
                f.write(self.txt_log.toPlainText())


# ──────────────────────────────────────────────────────────────────────────────
# Utility
# ──────────────────────────────────────────────────────────────────────────────

def _fmt_bytes(n: int) -> str:
    for unit in ("B","KB","MB","GB"):
        if n < 1024: return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ──────────────────────────────────────────────────────────────────────────────
# Main Window
# ──────────────────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.start_time = time.time()
        self.bridge = SignalBridge()
        self.log_handler = QtLogHandler()

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        root_logger.addHandler(self.log_handler)
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)-8s] %(name)s — %(message)s", datefmt="%H:%M:%S"
        ))
        root_logger.addHandler(console)
        self.logger = logging.getLogger("SecureCrypt.Main")

        self._init_window()
        self._init_tabs()
        self._init_status_bar()
        self._init_timers()
        self.logger.info("%s v%s started", Settings.APP_NAME, Settings.APP_VERSION)

    def _init_window(self):
        self.setWindowTitle(f"{Settings.APP_NAME}  ·  Encrypted Traffic Protection")
        self.setMinimumSize(1100, 720)
        self.resize(1280, 850)

    def _init_tabs(self):
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.setCentralWidget(self.tabs)

        self.tab_dashboard     = DashboardTab(self.bridge)
        self.tab_tunnel_server = TunnelServerTab(self.bridge)
        self.tab_tunnel_client = TunnelClientTab(self.bridge)
        self.tab_proxy         = ProxyTab(self.bridge)
        self.tab_e2e           = E2EMessagingTab(self.bridge)
        self.tab_crypto        = CryptoToolsTab()
        self.tab_keys          = KeyManagerTab(self.bridge)
        self.tab_logs          = LogsTab(self.log_handler)

        for tab, label in [
            (self.tab_dashboard,     "⚡ Dashboard"),
            (self.tab_tunnel_server, "🖧 Tunnel Server"),
            (self.tab_tunnel_client, "🌐 Tunnel Client"),
            (self.tab_proxy,         "🔀 Proxy"),
            (self.tab_e2e,           "💬 E2E Messaging"),
            (self.tab_crypto,        "🔐 Crypto Tools"),
            (self.tab_keys,          "🗝 Key Manager"),
            (self.tab_logs,          "📋 Logs"),
        ]:
            self.tabs.addTab(tab, label)

    def _init_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.lbl_status_main   = QLabel("Ready")
        self.lbl_status_cipher = QLabel("Cipher: —")
        self.lbl_status_cipher.setStyleSheet("color:#89b4fa; padding:0 12px;")
        self.lbl_status_time   = QLabel("")
        self.lbl_status_time.setStyleSheet("color:#6c7086; padding:0 8px;")

        self.status_bar.addWidget(self.lbl_status_main, 1)
        self.status_bar.addPermanentWidget(self.lbl_status_cipher)
        self.status_bar.addPermanentWidget(self.lbl_status_time)

        self.bridge.status_update.connect(self._update_status)

    def _update_status(self, msg: str):
        self.lbl_status_main.setText(msg)
        self.logger.info("Status: %s", msg)

    def _init_timers(self):
        self.dashboard_timer = QTimer(self)
        self.dashboard_timer.timeout.connect(self._refresh_dashboard)
        self.dashboard_timer.start(2000)

        self.clock_timer = QTimer(self)
        self.clock_timer.timeout.connect(self._tick_clock)
        self.clock_timer.start(1000)

    def _tick_clock(self):
        self.lbl_status_time.setText(datetime.now().strftime("%H:%M:%S"))

    def _refresh_dashboard(self):
        cipher = self.tab_tunnel_client.active_cipher or self.tab_proxy.active_cipher or "—"
        self.lbl_status_cipher.setText(f"Cipher: {cipher}")
        cipher_details = None
        if cipher != "—":
            try: cipher_details = CipherFactory.get_info(cipher)
            except ValueError: pass
        self.tab_dashboard.update_status(
            tunnel_running=self.tab_tunnel_server.is_running,
            proxy_running=self.tab_proxy.is_running,
            session_count=self.tab_tunnel_server.session_manager.active_count(),
            key_count=self.tab_keys.key_count,
            start_time=self.start_time,
            active_cipher=cipher,
            cipher_details=cipher_details,
        )

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


# ──────────────────────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────────────────────

def main():
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