from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QLabel, QLineEdit, QComboBox, QPushButton, QTextEdit, QWidget

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Integrity Checker")

        layout = QVBoxLayout()

        self.path_label = QLabel("File Path:")
        layout.addWidget(self.path_label)
        self.path_entry = QLineEdit()
        layout.addWidget(self.path_entry)

        self.algorithm_label = QLabel("Hash Algorithm:")
        layout.addWidget(self.algorithm_label)
        self.algorithm_menu = QComboBox()
        self.algorithm_menu.addItems(["md5", "sha1", "sha256", "sha512", "sha384"])
        layout.addWidget(self.algorithm_menu)

        self.check_button = QPushButton("Check Integrity")
        layout.addWidget(self.check_button)
        self.check_button.clicked.connect(self.check_integrity)

        self.result_output = QTextEdit()
        layout.addWidget(self.result_output)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def check_integrity(self):
        file_path = self.path_entry.text()
        hash_algorithm = self.algorithm_menu.currentText()
        # Call your existing functionality here, e.g.
        # result = your_function(file_path, hash_algorithm)
        result = "Integrity check result goes here."  # Placeholder
        self.result_output.setText(result)
