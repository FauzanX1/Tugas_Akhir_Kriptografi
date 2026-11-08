"""
SecureVault - Main Application Entry Point
Secure Communication & Data Protection System
Tugas Akhir Mata Kuliah Kriptografi
"""

import sys
import os
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from ui.style import DARK_THEME_QSS
from ui.login import LoginDialog
from ui.main_window import MainWindow
from config.database import db
from services.blockchain_service import BlockchainService

def main():
    # Setup high DPI display scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_THEME_QSS)

    # Ensure database connection and genesis block
    try:
        db.check_connection()
        BlockchainService.ensure_genesis_block()
    except Exception as e:
        print(f"[Warning] Inisialisasi awal database: {e}")

    # Launch Login Dialog
    login_dialog = LoginDialog()
    main_window = MainWindow()

    def on_authenticated(user_dict):
        main_window.update_user_session_ui()
        main_window.show()

    login_dialog.login_successful.connect(on_authenticated)

    # Show login modal
    if login_dialog.exec():
        sys.exit(app.exec())
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
