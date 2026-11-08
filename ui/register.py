"""
SecureVault - UI: User Registration Dialog
Provides account creation using Argon2id password hashing.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QFrame
)
from PySide6.QtCore import Qt
from services.auth_service import AuthService
from config.settings import APP_NAME

class RegisterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{APP_NAME} - Registrasi Akun Baru")
        self.setFixedSize(420, 520)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.registered_username = ""
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(16)

        title = QLabel("Daftar Pengguna Baru")
        title.setObjectName("TitleLabel")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        desc = QLabel("Password akan diamankan secara kriptografis menggunakan algoritma Argon2id (RFC 9106).")
        desc.setObjectName("SubtitleLabel")
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc)

        card = QFrame()
        card.setObjectName("Card")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(18, 18, 18, 18)
        c_layout.setSpacing(12)

        # Full Name
        c_layout.addWidget(QLabel("Nama Lengkap"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Contoh: John Doe")
        c_layout.addWidget(self.name_input)

        # Username
        c_layout.addWidget(QLabel("Username"))
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Pilih username unik")
        c_layout.addWidget(self.user_input)

        # Password
        c_layout.addWidget(QLabel("Master Password"))
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setPlaceholderText("Minimal 6 karakter")
        c_layout.addWidget(self.pwd_input)

        # Confirm Password
        c_layout.addWidget(QLabel("Konfirmasi Password"))
        self.pwd_confirm = QLineEdit()
        self.pwd_confirm.setEchoMode(QLineEdit.Password)
        self.pwd_confirm.setPlaceholderText("Ulangi password")
        c_layout.addWidget(self.pwd_confirm)

        layout.addWidget(card)

        # Register Button
        self.btn_submit = QPushButton("Buat Akun Vault")
        self.btn_submit.setObjectName("PrimaryBtn")
        self.btn_submit.setFixedHeight(40)
        self.btn_submit.clicked.connect(self._handle_register)
        layout.addWidget(self.btn_submit)

    def _handle_register(self):
        name = self.name_input.text().strip()
        user = self.user_input.text().strip()
        pwd = self.pwd_input.text()
        pwd_conf = self.pwd_confirm.text()

        if not user or not pwd:
            QMessageBox.warning(self, "Validasi Gagal", "Username dan password tidak boleh kosong.")
            return

        if pwd != pwd_conf:
            QMessageBox.warning(self, "Validasi Gagal", "Konfirmasi password tidak cocok!")
            return

        success, msg = AuthService.register(username=user, password=pwd, full_name=name)
        if success:
            QMessageBox.information(self, "Registrasi Berhasil", msg)
            self.registered_username = user
            self.accept()
        else:
            QMessageBox.critical(self, "Registrasi Gagal", msg)
