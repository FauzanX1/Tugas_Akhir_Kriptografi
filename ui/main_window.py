"""
SecureVault - UI: Main Application Window
Coordinates sidebar navigation, stacked views, user session header,
and memory key sanitization upon logout.
"""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QStackedWidget, QFrame, QMessageBox, QApplication
)
from PySide6.QtCore import Qt
from core.auth import session
from config.settings import APP_NAME, APP_SUBTITLE
from ui.dashboard import DashboardView
from ui.text_crypto import TextCryptoView
from ui.file_manager import FileManagerView
from ui.message import MessageView
from ui.steganography import SteganographyView
from ui.blockchain import BlockchainView
from ui.user_management import UserManagementView
from ui.settings import SettingsView

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} - {APP_SUBTITLE}")
        self.resize(1200, 800)
        self.setMinimumSize(1000, 680)
        self._init_ui()

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        root_layout = QHBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Left Sidebar Navigation Frame
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(240)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(14, 20, 14, 20)
        sb_layout.setSpacing(8)

        # App Brand Header in Sidebar
        brand_layout = QVBoxLayout()
        brand_layout.setSpacing(2)
        brand_title = QLabel(f"🛡️ {APP_NAME}")
        brand_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #38bdf8; padding: 4px;")
        brand_sub = QLabel("Security Suite")
        brand_sub.setStyleSheet("font-size: 11px; color: #64748b; padding-left: 6px;")
        brand_layout.addWidget(brand_title)
        brand_layout.addWidget(brand_sub)
        sb_layout.addLayout(brand_layout)
        sb_layout.addSpacing(16)

        # Navigation Buttons
        self.nav_buttons = []
        nav_items = [
            ("📊 Dashboard", 0),
            ("🔐 Text Encryption", 1),
            ("🗄️ File Vault", 2),
            ("💬 Secure Messages", 3),
            ("🖼️ Steganography", 4),
            ("⛓️ Blockchain Ledger", 5),
            ("👥 User Management", 6),
            ("⚙️ Settings & MFA", 7)
        ]

        for text, index in nav_items:
            btn = QPushButton(text)
            btn.setObjectName("NavBtn")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, idx=index: self._switch_view(idx))
            sb_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sb_layout.addStretch()

        # Logout Button at Sidebar Bottom
        self.btn_logout = QPushButton("🚪 Keluar (Logout)")
        self.btn_logout.setObjectName("DangerBtn")
        self.btn_logout.clicked.connect(self._handle_logout)
        sb_layout.addWidget(self.btn_logout)

        root_layout.addWidget(sidebar)

        # 2. Right Content Area (Header + Stacked Pages)
        content_area = QWidget()
        ca_layout = QVBoxLayout(content_area)
        ca_layout.setContentsMargins(0, 0, 0, 0)
        ca_layout.setSpacing(0)

        # Top Bar Header
        top_bar = QFrame()
        top_bar.setStyleSheet("background-color: #0d1527; border-bottom: 1px solid #1e293b;")
        top_bar.setFixedHeight(54)
        tb_layout = QHBoxLayout(top_bar)
        tb_layout.setContentsMargins(24, 0, 24, 0)

        self.lbl_current_page = QLabel("Dashboard")
        self.lbl_current_page.setStyleSheet("font-size: 15px; font-weight: bold; color: #f8fafc;")
        tb_layout.addWidget(self.lbl_current_page)
        tb_layout.addStretch()

        # Active User Pill
        self.lbl_user_pill = QLabel("👤 Pengguna Aktif")
        self.lbl_user_pill.setObjectName("BadgeInfo")
        tb_layout.addWidget(self.lbl_user_pill)

        ca_layout.addWidget(top_bar)

        # Stacked Pages
        self.stack = QStackedWidget()

        self.view_dashboard = DashboardView()
        self.view_text_crypto = TextCryptoView()
        self.view_file_manager = FileManagerView()
        self.view_message = MessageView()
        self.view_stego = SteganographyView()
        self.view_blockchain = BlockchainView()
        self.view_users = UserManagementView()
        self.view_settings = SettingsView()

        self.stack.addWidget(self.view_dashboard)       # 0
        self.stack.addWidget(self.view_text_crypto)     # 1
        self.stack.addWidget(self.view_file_manager)    # 2
        self.stack.addWidget(self.view_message)         # 3
        self.stack.addWidget(self.view_stego)           # 4
        self.stack.addWidget(self.view_blockchain)      # 5
        self.stack.addWidget(self.view_users)           # 6
        self.stack.addWidget(self.view_settings)        # 7

        ca_layout.addWidget(self.stack)
        root_layout.addWidget(content_area)

        # Initial active button
        self._switch_view(0)

    def update_user_session_ui(self):
        user = session.get_user()
        if user:
            display_name = user.get("full_name") or user.get("username")
            self.lbl_user_pill.setText(f"👤 {display_name} (ID: #{user['id']})")
        self.view_dashboard.refresh_data()

    def _switch_view(self, index: int):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)

        page_titles = [
            "Dashboard", "Text Super-Encryption", "File Encryption Vault",
            "Secure Messages", "Image Steganography", "Blockchain Ledger",
            "User Management", "Settings & Hardware Security"
        ]
        if index < len(page_titles):
            self.lbl_current_page.setText(page_titles[index])

        # Auto-refresh target views on navigation
        if index == 0:
            self.view_dashboard.refresh_data()
        elif index == 2:
            self.view_file_manager.refresh_table()
        elif index == 3:
            self.view_message.refresh_contacts()
        elif index == 5:
            self.view_blockchain.refresh_blocks()
        elif index == 6:
            self.view_users.refresh_users()
        elif index == 7:
            self.view_settings.load_user_settings()

    def _handle_logout(self):
        confirm = QMessageBox.question(
            self,
            "Konfirmasi Logout",
            "Apakah Anda yakin ingin keluar dari sesi SecureVault?\nKunci kriptografi dalam memori RAM akan dibersihkan.",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            session.logout()
            self.close()
            # Reopen login dialog
            from ui.login import LoginDialog
            dlg = LoginDialog()
            dlg.login_successful.connect(self._on_relogin)
            if dlg.exec():
                pass
            else:
                QApplication.quit()

    def _on_relogin(self, user):
        self.update_user_session_ui()
        self.show()
