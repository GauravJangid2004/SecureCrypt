import sys
import uuid
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QComboBox,
    QTableWidget, QTableWidgetItem, QMessageBox,
    QGroupBox
)
from PyQt6.QtCore import Qt


class KeyManagerUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureCrypt – Key Management")
        self.setGeometry(200, 100, 950, 600)

        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #eaeaea;
                font-family: Segoe UI;
                font-size: 13px;
            }
        """)

        self.keys = []  # In-memory key storage (replace with DB later)

        main_layout = QVBoxLayout(self)

        # ---------- Header ----------
        title = QLabel("Key Management")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: white;")
        main_layout.addWidget(title)

        subtitle = QLabel("Generate, view, rotate, and manage cryptographic keys securely")
        subtitle.setStyleSheet("color: #b0b0b0;")
        main_layout.addWidget(subtitle)

        main_layout.addSpacing(15)

        # ---------- Key Generation ----------
        gen_group = QGroupBox("Generate New Key")
        gen_group.setStyleSheet(self.group_style())
        gen_layout = QHBoxLayout()

        self.key_type_box = QComboBox()
        self.key_type_box.addItems(["AES-256", "RSA-2048"])
        self.key_type_box.setStyleSheet(self.combo_style())

        generate_btn = QPushButton("Generate Key")
        generate_btn.setStyleSheet(self.primary_button())
        generate_btn.clicked.connect(self.generate_key)

        gen_layout.addWidget(QLabel("Key Type:"))
        gen_layout.addWidget(self.key_type_box)
        gen_layout.addStretch()
        gen_layout.addWidget(generate_btn)

        gen_group.setLayout(gen_layout)
        main_layout.addWidget(gen_group)

        # ---------- Key Table ----------
        table_group = QGroupBox("Stored Keys")
        table_group.setStyleSheet(self.group_style())
        table_layout = QVBoxLayout()

        self.key_table = QTableWidget(0, 4)
        self.key_table.setHorizontalHeaderLabels(
            ["Key ID", "Type", "Length", "Created On"]
        )
        self.key_table.horizontalHeader().setStretchLastSection(True)
        self.key_table.setStyleSheet(self.table_style())

        table_layout.addWidget(self.key_table)
        table_group.setLayout(table_layout)
        main_layout.addWidget(table_group)

        # ---------- Action Buttons ----------
        action_layout = QHBoxLayout()

        delete_btn = QPushButton("Delete Key")
        rotate_btn = QPushButton("Rotate Key")

        delete_btn.setStyleSheet(self.danger_button())
        rotate_btn.setStyleSheet(self.secondary_button())

        delete_btn.clicked.connect(self.delete_key)
        rotate_btn.clicked.connect(self.rotate_key)

        action_layout.addStretch()
        action_layout.addWidget(delete_btn)
        action_layout.addWidget(rotate_btn)

        main_layout.addLayout(action_layout)
        main_layout.addStretch()

    # ---------- Logic ----------
    def generate_key(self):
        key_type = self.key_type_box.currentText()
        key_id = str(uuid.uuid4())[:8]
        length = "256-bit" if "AES" in key_type else "2048-bit"
        created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        key_data = {
            "id": key_id,
            "type": key_type,
            "length": length,
            "created": created
        }
        self.keys.append(key_data)
        self.refresh_table()

    def delete_key(self):
        row = self.key_table.currentRow()
        if row == -1:
            self.show_warning("Please select a key to delete.")
            return

        reply = QMessageBox.question(
            self, "Confirm Deletion",
            "Are you sure you want to delete this key?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.keys.pop(row)
            self.refresh_table()

    def rotate_key(self):
        row = self.key_table.currentRow()
        if row == -1:
            self.show_warning("Please select a key to rotate.")
            return

        self.keys[row]["created"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.refresh_table()

    def refresh_table(self):
        self.key_table.setRowCount(0)
        for key in self.keys:
            row = self.key_table.rowCount()
            self.key_table.insertRow(row)
            self.key_table.setItem(row, 0, QTableWidgetItem(key["id"]))
            self.key_table.setItem(row, 1, QTableWidgetItem(key["type"]))
            self.key_table.setItem(row, 2, QTableWidgetItem(key["length"]))
            self.key_table.setItem(row, 3, QTableWidgetItem(key["created"]))

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

    def table_style(self):
        return """
            QTableWidget {
                background-color: #f5f6f7;      /* Light background */
                color: #2c3e50;                 /* DARK TEXT */
                border-radius: 6px;
                gridline-color: #2c3e50;
                selection-background-color: #2c7be5;
                selection-color: white;
            }

            QTableWidget::item {
                padding: 6px;
            }

            QTableWidget::item:selected {
                background-color: #2c7be5;
                color: white;
            }

            QHeaderView::section {
                background-color: #e1e4e8;
                color: #2c3e50;                 /* DARK HEADER TEXT */
                font-weight: bold;
                padding: 8px;
                border: #2c3e50;
            }
        """


    def primary_button(self):
        return """
            QPushButton {
                background-color: #2c7be5;
                color: white;
                padding: 10px 25px;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1a68d1;
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

    def danger_button(self):
        return """
            QPushButton {
                background-color: #e74c3c;
                color: white;
                padding: 10px 25px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """


# ---------- Run ----------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = KeyManagerUI()
    window.show()
    sys.exit(app.exec())
