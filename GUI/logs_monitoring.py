import sys
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QComboBox,
    QTableWidget, QTableWidgetItem, QGroupBox
)
from PyQt6.QtCore import Qt


class LogsMonitoringUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureCrypt – Logs & Monitoring")
        self.setGeometry(250, 120, 1000, 600)

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
        title = QLabel("Logs & Monitoring")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: white;")
        main_layout.addWidget(title)

        subtitle = QLabel(
            "Monitor encryption and decryption operations for transparency and debugging"
        )
        subtitle.setStyleSheet("color: #b0b0b0;")
        main_layout.addWidget(subtitle)

        main_layout.addSpacing(15)

        # ---------- Filters ----------
        filter_group = QGroupBox("Filter Logs")
        filter_group.setStyleSheet(self.group_style())
        filter_layout = QHBoxLayout()

        self.operation_filter = QComboBox()
        self.operation_filter.addItems(
            ["All Operations", "Encrypt", "Decrypt"]
        )
        self.operation_filter.setStyleSheet(self.combo_style())

        self.algorithm_filter = QComboBox()
        self.algorithm_filter.addItems(
            ["All Algorithms", "AES-256", "RSA-2048", "Hybrid"]
        )
        self.algorithm_filter.setStyleSheet(self.combo_style())

        filter_layout.addWidget(QLabel("Operation:"))
        filter_layout.addWidget(self.operation_filter)
        filter_layout.addSpacing(20)
        filter_layout.addWidget(QLabel("Algorithm:"))
        filter_layout.addWidget(self.algorithm_filter)
        filter_layout.addStretch()

        filter_group.setLayout(filter_layout)
        main_layout.addWidget(filter_group)

        # ---------- Logs Table ----------
        table_group = QGroupBox("Encryption Activity Logs")
        table_group.setStyleSheet(self.group_style())
        table_layout = QVBoxLayout()

        self.log_table = QTableWidget(0, 5)
        self.log_table.setHorizontalHeaderLabels([
            "Timestamp", "Operation", "Algorithm", "Target", "Status"
        ])
        self.log_table.horizontalHeader().setStretchLastSection(True)
        self.log_table.setStyleSheet(self.table_style())
        self.log_table.setAlternatingRowColors(True)

        table_layout.addWidget(self.log_table)
        table_group.setLayout(table_layout)
        main_layout.addWidget(table_group)

        # ---------- Actions ----------
        action_layout = QHBoxLayout()

        add_dummy_btn = QPushButton("Add Test Log")
        clear_btn = QPushButton("Clear Logs")

        add_dummy_btn.setStyleSheet(self.primary_button())
        clear_btn.setStyleSheet(self.danger_button())

        add_dummy_btn.clicked.connect(self.add_dummy_log)
        clear_btn.clicked.connect(self.clear_logs)

        action_layout.addStretch()
        action_layout.addWidget(add_dummy_btn)
        action_layout.addWidget(clear_btn)

        main_layout.addLayout(action_layout)
        main_layout.addStretch()

    # ---------- Logic ----------
    def add_dummy_log(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        operation = "Encrypt"
        algorithm = "AES-256"
        target = "Text"
        status = "Success"

        row = self.log_table.rowCount()
        self.log_table.insertRow(row)

        self.log_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.log_table.setItem(row, 1, QTableWidgetItem(operation))
        self.log_table.setItem(row, 2, QTableWidgetItem(algorithm))
        self.log_table.setItem(row, 3, QTableWidgetItem(target))

        status_item = QTableWidgetItem(status)
        status_item.setForeground(Qt.GlobalColor.green)
        self.log_table.setItem(row, 4, status_item)

    def clear_logs(self):
        self.log_table.setRowCount(0)

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
                background-color: #2b2b2b;
                color: #eaeaea;
                gridline-color: #3c3f41;
                border-radius: 6px;
            }

            QTableWidget::item {
                padding: 8px;
            }

            QTableWidget::item:alternate {
                background-color: #242424;
            }

            QTableWidget::item:selected {
                background-color: #2c7be5;
                color: white;
            }

            QHeaderView::section {
                background-color: #1f1f1f;
                color: #eaeaea;
                font-weight: bold;
                padding: 8px;
                border: 1px solid #3c3f41;
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
    window = LogsMonitoringUI()
    window.show()
    sys.exit(app.exec())
