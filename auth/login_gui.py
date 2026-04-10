"""
SecureCrypt Zero Trust Login GUI
Integrates with main.py — shown before the main window opens.
"""

import time
import logging
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QFormLayout, QGroupBox,
    QMessageBox, QFrame, QProgressBar,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor

from auth.login_system import ZeroTrustLoginManager

logger = logging.getLogger("SecureCrypt.LoginGUI")

# ─────────────────────────────────────────────────────────────
# Stylesheet — matches SecureCrypt dark theme
# ─────────────────────────────────────────────────────────────
LOGIN_STYLE = """
QDialog {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: 'Segoe UI', sans-serif;
}
QLabel {
    color: #cdd6f4;
    font-size: 13px;
}
QLineEdit {
    background-color: #181825;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 14px;
    min-height: 38px;
}
QLineEdit:focus {
    border: 1px solid #89b4fa;
    background-color: #1e1e2e;
}
QPushButton {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 7px;
    padding: 10px 24px;
    font-size: 14px;
    font-weight: bold;
    min-height: 40px;
}
QPushButton:hover { background-color: #45475a; color: #89b4fa; }
QPushButton[role="primary"] {
    background-color: #89b4fa;
    color: #1e1e2e;
    border: none;
    font-weight: bold;
}
QPushButton[role="primary"]:hover { background-color: #74c7ec; }
QPushButton[role="danger"] {
    color: #f38ba8;
    border-color: #f38ba8;
}
QGroupBox {
    color: #89b4fa;
    border: 1px solid #313244;
    border-radius: 10px;
    margin-top: 16px;
    padding: 16px 14px 12px 14px;
    font-size: 13px;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 16px;
    padding: 0 8px;
    background: #1e1e2e;
    font-size: 13px;
}
QProgressBar {
    border: 1px solid #313244;
    border-radius: 4px;
    background: #181825;
    text-align: center;
    color: #cdd6f4;
    font-size: 11px;
    min-height: 20px;
}
QProgressBar::chunk { background: #89b4fa; border-radius: 4px; }
"""


class LoginDialog(QDialog):
    """
    Zero Trust Login Dialog.
    Shown at application startup — user must authenticate
    before the main window is accessible.
    """

    def __init__(self, auth_manager: ZeroTrustLoginManager,
                 parent=None):
        super().__init__(parent)
        self.auth = auth_manager
        self.token: str | None = None
        self.username_result: str = ""
        self._ip = "127.0.0.1"  # local app login

        self.setWindowTitle("SecureCrypt — Secure Login")
        self.setFixedSize(600, 800)
        self.setModal(True)
        self.setStyleSheet(LOGIN_STYLE)
        # Prevent closing without logging in
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.CustomizeWindowHint
            | Qt.WindowType.WindowTitleHint
        )

        self._build_ui()
        self._start_clock()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(36, 30, 36, 30)

        # Header
        title = QLabel("SecureCrypt")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color:#cba6f7; letter-spacing:2px; min-height:40px;")
        layout.addWidget(title)

        sub = QLabel("Zero Trust Authentication Required")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet("color:#6c7086; font-size:12px; min-height:24px;")
        layout.addWidget(sub)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#313244; min-height:2px;")
        layout.addWidget(sep)

        # Credentials group
        cred_group = QGroupBox("Credentials")
        form = QFormLayout(cred_group)
        form.setSpacing(14)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self.txt_user = QLineEdit()
        self.txt_user.setPlaceholderText("Enter username")
        self.txt_user.setMinimumHeight(42)

        self.txt_pass = QLineEdit()
        self.txt_pass.setPlaceholderText("Enter password (min 12 chars)")
        self.txt_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_pass.setMinimumHeight(42)

        self.txt_totp = QLineEdit()
        self.txt_totp.setPlaceholderText("6-digit TOTP code")
        self.txt_totp.setMaxLength(6)
        self.txt_totp.setMinimumHeight(42)

        form.addRow("Username:", self.txt_user)
        form.addRow("Password:", self.txt_pass)
        form.addRow("TOTP Code:", self.txt_totp)

        cred_group.setMinimumHeight(180)
        layout.addWidget(cred_group)

        # Status label
        self.lbl_status = QLabel("")
        self.lbl_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setStyleSheet(
            "color:#f38ba8; font-size:13px; min-height:28px; font-weight: bold;"
        )
        layout.addWidget(self.lbl_status)

        # Lockout countdown
        self.lbl_lockout = QLabel("")
        self.lbl_lockout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_lockout.setStyleSheet(
            "color:#f9e2af; font-size:12px; min-height:24px;"
        )
        layout.addWidget(self.lbl_lockout)

        # Attempt counter progress bar
        attempts_group = QGroupBox("Login Attempts")
        attempts_layout = QVBoxLayout(attempts_group)
        attempts_layout.setContentsMargins(12, 12, 12, 12)
        self.pb_attempts = QProgressBar()
        self.pb_attempts.setRange(0, 5)
        self.pb_attempts.setValue(0)
        self.pb_attempts.setFormat("%v / 5 attempts")
        self.pb_attempts.setStyleSheet(
            "QProgressBar::chunk { background: #f38ba8; }"
        )
        self.pb_attempts.setMinimumHeight(24)
        attempts_layout.addWidget(self.pb_attempts)
        attempts_group.setMinimumHeight(80)
        layout.addWidget(attempts_group)

        # Security info
        info_group = QGroupBox("Zero Trust Policy")
        info_layout = QVBoxLayout(info_group)
        info_layout.setContentsMargins(12, 12, 12, 12)
        info_text = QLabel(
            "🔑  Session keys rotate every 10 minutes\n"
            "🛡  TOTP required on every login\n"
            "⏱  Sessions expire after 30 min idle\n"
            "🔒  5 failed attempts = 5 min lockout"
        )
        info_text.setStyleSheet("color:#a6adc8; font-size:12px; line-height:1.6;")
        info_text.setMinimumHeight(80)
        info_layout.addWidget(info_text)
        info_group.setMinimumHeight(110)
        layout.addWidget(info_group)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        self.btn_login = QPushButton(" Login")
        self.btn_login.setProperty("role", "primary")
        self.btn_login.setMinimumHeight(44)
        self.btn_login.setMinimumWidth(120)
        self.btn_login.clicked.connect(self._do_login)
        self.txt_pass.returnPressed.connect(self._do_login)
        self.txt_totp.returnPressed.connect(self._do_login)

        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_login)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Time display
        self.lbl_time = QLabel("")
        self.lbl_time.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.lbl_time.setStyleSheet("color:#45475a; font-size:11px; min-height:20px;")
        layout.addWidget(self.lbl_time)

    def _start_clock(self):
        self._clock = QTimer(self)
        self._clock.timeout.connect(self._tick)
        self._clock.start(1000)

    def _tick(self):
        import datetime
        self.lbl_time.setText(
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

    def _do_login(self):
        username = self.txt_user.text().strip()
        password = self.txt_pass.text()
        totp     = self.txt_totp.text().strip()

        if not username or not password or not totp:
            self.lbl_status.setText(
                "⚠ All fields required (username, password, TOTP)"
            )
            return

        self.btn_login.setEnabled(False)
        self.lbl_status.setText("🔄 Verifying credentials…")

        token = self.auth.login(
            username=username,
            password=password,
            totp_code=totp,
            ip=self._ip,
        )

        if token:
            self.token            = token
            self.username_result  = username
            self.lbl_status.setStyleSheet("color:#a6e3a1;")
            self.lbl_status.setText("✅ Authentication successful!")
            self._clock.stop()
            QTimer.singleShot(600, self.accept)
        else:
            self.txt_pass.clear()
            self.txt_totp.clear()
            self.btn_login.setEnabled(True)

            # Update attempt counter display
            from auth.login_system import MAX_LOGIN_ATTEMPTS
            user = self.auth._users.get(username)
            if user:
                attempts = user.failed_attempts
                self.pb_attempts.setValue(min(attempts, 5))

                if user.locked_until > time.time():
                    remaining = int(user.locked_until - time.time())
                    self.lbl_status.setText(
                        f"🔒 Account locked — retry in {remaining}s"
                    )
                    self._start_lockout_countdown(
                        user.locked_until
                    )
                else:
                    remaining = MAX_LOGIN_ATTEMPTS - attempts
                    self.lbl_status.setText(
                        f"❌ Authentication failed — "
                        f"{remaining} attempt(s) remaining"
                    )
            else:
                self.lbl_status.setText(
                    "❌ Authentication failed"
                )

    def _start_lockout_countdown(self, unlock_time: float):
        def _countdown():
            remaining = int(unlock_time - time.time())
            if remaining > 0:
                self.lbl_lockout.setText(
                    f"⏳ Lockout: {remaining}s remaining"
                )
                self.btn_login.setEnabled(False)
            else:
                self.lbl_lockout.setText("")
                self.btn_login.setEnabled(True)
                self._lockout_timer.stop()

        self._lockout_timer = QTimer(self)
        self._lockout_timer.timeout.connect(_countdown)
        self._lockout_timer.start(1000)
        _countdown()