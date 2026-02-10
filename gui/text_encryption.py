import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QTextEdit,
    QPushButton, QVBoxLayout, QHBoxLayout,
    QComboBox, QGroupBox, QMessageBox
)
from PyQt6.QtCore import Qt


class TextEncryptionUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureCrypt – Text Encryption")
        self.setGeometry(200, 100, 900, 600)

        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #eaeaea;
                font-family: Segoe UI;
                font-size: 13px;
            }
        """)

        main_layout = QVBoxLayout(self)

        # ---------- Header ----------
        title = QLabel("Text Encryption / Decryption")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: white;")
        main_layout.addWidget(title)

        subtitle = QLabel("Encrypt or decrypt text using secure cryptographic algorithms")
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

        # ---------- Input Box ----------
        input_group = QGroupBox("Input Text")
        input_group.setStyleSheet(self.group_style())
        input_layout = QVBoxLayout()

        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter plain text or cipher text here...")
        self.input_text.setStyleSheet(self.textbox_style())

        input_layout.addWidget(self.input_text)
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)

        # ---------- Buttons ----------
        btn_layout = QHBoxLayout()

        encrypt_btn = QPushButton("Encrypt")
        decrypt_btn = QPushButton("Decrypt")

        encrypt_btn.setStyleSheet(self.primary_button())
        decrypt_btn.setStyleSheet(self.secondary_button())

        encrypt_btn.clicked.connect(self.encrypt_text)
        decrypt_btn.clicked.connect(self.decrypt_text)

        btn_layout.addStretch()
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)
        btn_layout.addStretch()

        main_layout.addLayout(btn_layout)

        # ---------- Output Box ----------
        output_group = QGroupBox("Output")
        output_group.setStyleSheet(self.group_style())
        output_layout = QVBoxLayout()

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Encrypted or decrypted output will appear here...")
        self.output_text.setStyleSheet(self.textbox_style())

        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group)

        main_layout.addStretch()

    # ---------- Dummy Logic (Replace with real crypto later) ----------
    def encrypt_text(self):
        text = self.input_text.toPlainText()
        if not text:
            self.show_warning("Please enter text to encrypt.")
            return
        algo = self.algorithm_box.currentText()
        self.output_text.setText(f"[{algo} ENCRYPTED]\n{text[::-1]}")

    def decrypt_text(self):
        text = self.input_text.toPlainText()
        if not text:
            self.show_warning("Please enter text to decrypt.")
            return
        algo = self.algorithm_box.currentText()
        self.output_text.setText(f"[{algo} DECRYPTED]\n{text[::-1]}")

    def show_warning(self, msg):
        QMessageBox.warning(self, "Input Required", msg)

    # ---------- Styles ----------
    def textbox_style(self):
        return """
            QTextEdit {
                background-color: #f5f6f7;
                color: #2c3e50;
                border-radius: 6px;
                padding: 8px;
            }
        """

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


# ---------- Run ----------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TextEncryptionUI()
    window.show()
    sys.exit(app.exec())
