import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QFileDialog,
    QComboBox, QTextEdit, QGroupBox, QMessageBox
)
from PyQt6.QtCore import Qt


class FileEncryptionUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureCrypt – File Encryption")
        self.setGeometry(200, 100, 950, 650)

        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #eaeaea;
                font-family: Segoe UI;
                font-size: 13px;
            }
        """)

        self.selected_file = None

        main_layout = QVBoxLayout(self)

        # ---------- Header ----------
        title = QLabel("File Encryption / Decryption")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: white;")
        main_layout.addWidget(title)

        subtitle = QLabel("Encrypt or decrypt files securely using cryptographic algorithms")
        subtitle.setStyleSheet("color: #b0b0b0;")
        main_layout.addWidget(subtitle)

        main_layout.addSpacing(15)

        # ---------- Controls ----------
        controls = QHBoxLayout()

        algo_label = QLabel("Algorithm:")
        self.algorithm_box = QComboBox()
        self.algorithm_box.addItems(["AES-256", "RSA-2048", "Hybrid"])
        self.algorithm_box.setStyleSheet(self.combo_style())

        key_label = QLabel("Key:")
        self.key_box = QComboBox()
        self.key_box.addItems(["Default Key", "User Key 1", "User Key 2"])
        self.key_box.setStyleSheet(self.combo_style())

        controls.addWidget(algo_label)
        controls.addWidget(self.algorithm_box)
        controls.addSpacing(20)
        controls.addWidget(key_label)
        controls.addWidget(self.key_box)
        controls.addStretch()

        main_layout.addLayout(controls)

        # ---------- File Picker ----------
        file_group = QGroupBox("Select File")
        file_group.setStyleSheet(self.group_style())
        file_layout = QHBoxLayout()

        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("color:#b0b0b0;")

        browse_btn = QPushButton("Browse")
        browse_btn.setStyleSheet(self.secondary_button())
        browse_btn.clicked.connect(self.browse_file)

        file_layout.addWidget(self.file_label)
        file_layout.addStretch()
        file_layout.addWidget(browse_btn)
        file_group.setLayout(file_layout)

        main_layout.addWidget(file_group)

        # ---------- File Info ----------
        info_group = QGroupBox("File Information")
        info_group.setStyleSheet(self.group_style())
        info_layout = QHBoxLayout()

        self.size_before = QLabel("Size before: —")
        self.size_after = QLabel("Size after: —")

        info_layout.addWidget(self.size_before)
        info_layout.addStretch()
        info_layout.addWidget(self.size_after)

        info_group.setLayout(info_layout)
        main_layout.addWidget(info_group)

        # ---------- Action Buttons ----------
        action_layout = QHBoxLayout()

        encrypt_btn = QPushButton("Encrypt File")
        decrypt_btn = QPushButton("Decrypt File")

        encrypt_btn.setStyleSheet(self.primary_button())
        decrypt_btn.setStyleSheet(self.secondary_button())

        encrypt_btn.clicked.connect(self.encrypt_file)
        decrypt_btn.clicked.connect(self.decrypt_file)

        action_layout.addStretch()
        action_layout.addWidget(encrypt_btn)
        action_layout.addWidget(decrypt_btn)
        action_layout.addStretch()

        main_layout.addLayout(action_layout)

        # ---------- Status Logs ----------
        log_group = QGroupBox("Status Logs")
        log_group.setStyleSheet(self.group_style())
        log_layout = QVBoxLayout()

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet(self.log_style())

        log_layout.addWidget(self.log_box)
        log_group.setLayout(log_layout)

        main_layout.addWidget(log_group)

        main_layout.addStretch()

    # ---------- Logic (Dummy for Now) ----------
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.selected_file = file_path
            self.file_label.setText(os.path.basename(file_path))
            size = os.path.getsize(file_path) / 1024
            self.size_before.setText(f"Size before: {size:.2f} KB")
            self.size_after.setText("Size after: —")
            self.log("File selected successfully.", success=True)

    def encrypt_file(self):
        if not self.selected_file:
            self.show_warning("Please select a file first.")
            return
        algo = self.algorithm_box.currentText()
        self.size_after.setText("Size after:  (encrypted)")
        self.log(f"File encrypted using {algo}.", success=True)

    def decrypt_file(self):
        if not self.selected_file:
            self.show_warning("Please select a file first.")
            return
        algo = self.algorithm_box.currentText()
        self.size_after.setText("Size after:  (decrypted)")
        self.log(f"File decrypted using {algo}.", success=True)

    # ---------- Utilities ----------
    def log(self, message, success=True):
        color = "#2ecc71" if success else "#e74c3c"
        self.log_box.append(f"<span style='color:{color};'>• {message}</span>")

    def show_warning(self, msg):
        QMessageBox.warning(self, "Action Required", msg)

    # ---------- Styles ----------
    def combo_style(self):
        return """
            QComboBox {
                background-color: #f5f6f7;
                color: #2c3e50;
                padding: 6px;
                border-radius: 6px;
            }
            QComboBox:hover {
                background-color: #e6e9ed;
            }
        """

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
                padding: 10px 30px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #2c3e50;
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
    window = FileEncryptionUI()
    window.show()
    sys.exit(app.exec())
