import sys
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QTextEdit,
    QGroupBox, QMessageBox
)
from PyQt6.QtCore import Qt


class APIPanelUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureCrypt – API & Traffic Encryption")
        self.setGeometry(250, 120, 900, 600)

        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #eaeaea;
                font-family: Segoe UI;
                font-size: 13px;
            }
        """)

        self.api_running = True
        self.api_endpoint = "http://127.0.0.1:8000/encrypt"

        main_layout = QVBoxLayout(self)

        # ---------- Header ----------
        title = QLabel("API & Traffic Encryption Panel")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: white;")
        main_layout.addWidget(title)

        subtitle = QLabel(
            "Manage local encryption API and monitor encrypted traffic"
        )
        subtitle.setStyleSheet("color: #b0b0b0;")
        main_layout.addWidget(subtitle)

        main_layout.addSpacing(20)

        # ---------- API Status ----------
        status_group = QGroupBox("API Status")
        status_group.setStyleSheet(self.group_style())
        status_layout = QHBoxLayout()

        self.status_label = QLabel("RUNNING")
        self.status_label.setStyleSheet(self.status_running())

        toggle_btn = QPushButton("Start / Stop API")
        toggle_btn.setStyleSheet(self.secondary_button())
        toggle_btn.clicked.connect(self.toggle_api)

        status_layout.addWidget(QLabel("Current Status:"))
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(toggle_btn)

        status_group.setLayout(status_layout)
        main_layout.addWidget(status_group)

        # ---------- API Endpoint ----------
        endpoint_group = QGroupBox("Local API Endpoint")
        endpoint_group.setStyleSheet(self.group_style())
        endpoint_layout = QHBoxLayout()

        endpoint_label = QLabel(self.api_endpoint)
        endpoint_label.setStyleSheet("""
            QLabel {
                background-color: #2b2b2b;
                padding: 8px;
                border-radius: 6px;
            }
        """)

        endpoint_layout.addWidget(endpoint_label)
        endpoint_group.setLayout(endpoint_layout)

        main_layout.addWidget(endpoint_group)

        # ---------- Test Request ----------
        test_group = QGroupBox("Test Encryption Request")
        test_group.setStyleSheet(self.group_style())
        test_layout = QHBoxLayout()

        test_btn = QPushButton("Send Test Encryption Request")
        test_btn.setStyleSheet(self.primary_button())
        test_btn.clicked.connect(self.test_request)

        test_layout.addStretch()
        test_layout.addWidget(test_btn)
        test_layout.addStretch()

        test_group.setLayout(test_layout)
        main_layout.addWidget(test_group)

        # ---------- Logs ----------
        log_group = QGroupBox("Encrypted API Traffic Logs")
        log_group.setStyleSheet(self.group_style())
        log_layout = QVBoxLayout()

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet(self.log_style())

        log_layout.addWidget(self.log_box)
        log_group.setLayout(log_layout)

        main_layout.addWidget(log_group)
        main_layout.addStretch()

    # ---------- Logic ----------
    def toggle_api(self):
        self.api_running = not self.api_running
        if self.api_running:
            self.status_label.setText("RUNNING")
            self.status_label.setStyleSheet(self.status_running())
            self.log("API started successfully.", success=True)
        else:
            self.status_label.setText("STOPPED")
            self.status_label.setStyleSheet(self.status_stopped())
            self.log("API stopped.", success=False)

    def test_request(self):
        if not self.api_running:
            QMessageBox.warning(
                self, "API Not Running",
                "Please start the API before sending requests."
            )
            return

        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log(
            f"[{timestamp}] Encrypted request sent to {self.api_endpoint}",
            success=True
        )

    def log(self, message, success=True):
        color = "#2ecc71" if success else "#e74c3c"
        self.log_box.append(
            f"<span style='color:{color};'>• {message}</span>"
        )

    # ---------- Styles ----------
    def group_style(self):
        return """
            QGroupBox {
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                margin-top: 10px;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                color: #9cdcfe;
            }
        """

    def primary_button(self):
        return """
            QPushButton {
                background-color: #2c7be5;
                color: white;
                padding: 10px 30px;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1a68d1;
            }
            QPushButton:pressed {
                background-color: #1557b0;
            }
        """

    def secondary_button(self):
        return """
            QPushButton {
                background-color: #34495e;
                color: white;
                padding: 10px 25px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #2c3e50;
            }
        """

    def status_running(self):
        return """
            QLabel {
                background-color: #eafaf1;
                color: #2ecc71;
                padding: 6px 15px;
                border-radius: 6px;
                font-weight: bold;
            }
        """

    def status_stopped(self):
        return """
            QLabel {
                background-color: #fdecea;
                color: #e74c3c;
                padding: 6px 15px;
                border-radius: 6px;
                font-weight: bold;
            }
        """

    def log_style(self):
        return """
            QTextEdit {
                background-color: #111;
                color: #eaeaea;
                border-radius: 6px;
                padding: 8px;
            }
        """


# ---------- Run ----------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = APIPanelUI()
    window.show()
    sys.exit(app.exec())
