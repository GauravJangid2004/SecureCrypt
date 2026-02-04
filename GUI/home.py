import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel,
    QPushButton, QVBoxLayout, QHBoxLayout,
    QListWidget, QFrame, QComboBox, QMessageBox
)
from PyQt6.QtCore import Qt


class SecureCryptDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureCrypt Dashboard")
        self.setGeometry(100, 60, 1200, 700)

        # ---------- Central Widget ----------
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)

        # ---------- Sidebar ----------
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(230)
        self.sidebar.addItems([
            "Dashboard",
            "Text Encryption",
            "File Encryption",
            "Key Manager",
            "Logs"
        ])
        self.sidebar.setCurrentRow(0)
        self.sidebar.setStyleSheet("""
            QListWidget {
                background: #f4f6f8;
                color: #2c3e50;              /* BLACK TEXT */
                font-size: 14px;
                border: none;
            }

            QListWidget::item {
                padding: 14px;
            }

            QListWidget::item:selected {
                background: #2c7be5;
                color: white;
                font-weight: bold;
                border-radius: 6px;
                margin: 4px;
            }

            QListWidget::item:hover {
                background: #dde6f0;
            }
        """)

        main_layout.addWidget(self.sidebar)

        # ---------- Content Area ----------
        content = QVBoxLayout()
        main_layout.addLayout(content)

        # ---------- Header ----------
        header = QLabel("SecureCrypt – Encryption Dashboard")
        header.setStyleSheet("font-size:20px; font-weight:bold;")
        content.addWidget(header)

        sub = QLabel("Unified Cryptography-Based Security Platform")
        sub.setStyleSheet("color:gray;")
        content.addWidget(sub)

        content.addSpacing(15)

        # ---------- Status Cards ----------
        cards = QHBoxLayout()

        self.api_status = QLabel("API Status: RUNNING")
        self.api_status.setStyleSheet(self.green_card())

        self.algorithm_status = QLabel("Active Algorithm: AES-256")
        self.algorithm_status.setStyleSheet(self.blue_card())

        cards.addWidget(self.api_status)
        cards.addWidget(self.algorithm_status)

        content.addLayout(cards)

        # ---------- Controls ----------
        controls = QHBoxLayout()

        self.algorithm_select = QComboBox()
        self.algorithm_select.addItems(["AES-256", "RSA-2048", "Hybrid"])
        self.algorithm_select.currentTextChanged.connect(self.change_algorithm)

        toggle_api_btn = QPushButton("Start / Stop API")
        toggle_api_btn.clicked.connect(self.toggle_api)

        controls.addWidget(QLabel("Select Algorithm:"))
        controls.addWidget(self.algorithm_select)
        controls.addStretch()
        controls.addWidget(toggle_api_btn)

        content.addSpacing(15)
        content.addLayout(controls)

        # ---------- Quick Actions ----------
        actions = QHBoxLayout()

        encrypt_text_btn = QPushButton("Encrypt Text")
        encrypt_file_btn = QPushButton("Encrypt File")
        key_manager_btn = QPushButton("Key Manager")

        for btn in [encrypt_text_btn, encrypt_file_btn, key_manager_btn]:
            btn.setFixedHeight(45)
            btn.setStyleSheet(self.action_button())
            btn.clicked.connect(self.not_implemented)

        actions.addWidget(encrypt_text_btn)
        actions.addWidget(encrypt_file_btn)
        actions.addWidget(key_manager_btn)

        content.addSpacing(20)
        content.addLayout(actions)

        # ---------- Warning ----------
        warning = QLabel("⚠ 8 systems require user action to complete encryption.")
        warning.setStyleSheet("color:#c0392b; font-weight:bold;")
        content.addSpacing(25)
        content.addWidget(warning)

        content.addStretch()

        # ---------- Footer ----------
        footer = QLabel("Status: Ready")
        footer.setAlignment(Qt.AlignmentFlag.AlignRight)
        footer.setStyleSheet("color:gray;")
        content.addWidget(footer)

        # Internal state
        self.api_running = True

    # ---------- Styles ----------
    def green_card(self):
        return """
            QLabel {
                background:#eafaf1;
                border:1px solid #2ecc71;
                padding:15px;
                font-weight:bold;
            }
        """

    def blue_card(self):
        return """
            QLabel {
                background:#ebf3ff;
                border:1px solid #3498db;
                padding:15px;
                font-weight:bold;
            }
        """

    def action_button(self):
        return """
            QPushButton {
                background:#2c3e50;
                color:white;
                font-size:14px;
                border-radius:6px;
            }
            QPushButton:hover {
                background:#34495e;
            }
        """

    # ---------- Interactions ----------
    def toggle_api(self):
        self.api_running = not self.api_running
        if self.api_running:
            self.api_status.setText("API Status: RUNNING")
            self.api_status.setStyleSheet(self.green_card())
        else:
            self.api_status.setText("API Status: STOPPED")
            self.api_status.setStyleSheet("""
                QLabel {
                    background:#fdecea;
                    border:1px solid #e74c3c;
                    padding:15px;
                    font-weight:bold;
                }
            """)

    def change_algorithm(self, algo):
        self.algorithm_status.setText(f"Active Algorithm: {algo}")

    def not_implemented(self):
        QMessageBox.information(
            self,
            "Coming Soon",
            "This module will be implemented in the next phase."
        )


# ---------- Run ----------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureCryptDashboard()
    window.show()
    sys.exit(app.exec())
