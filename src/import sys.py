import sys

from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel


app = QApplication(sys.argv)

window = QMainWindow()
window.setWindowTitle("CAN-Sentinel Test")
window.resize(1000, 600)

label = QLabel("CAN-Sentinel Dashboard Test")
label.setStyleSheet("font-size: 30px;")

window.setCentralWidget(label)

window.show()

sys.exit(app.exec_())