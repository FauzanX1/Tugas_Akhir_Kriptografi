"""
SecureVault - UI: Login Window
Provides authentication with Argon2id password verification,
Windows Hello biometrics, and physical/virtual USB Dongle verification.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QFrame, QCheckBox
)
from PySide6.QtCore import Qt, Signal
from services.auth_service import AuthService
from hardware.biometric import BiometricAuth
from hardware.dongle import USBDongleAuth
from config.settings import DEV_MODE, APP_NAME, APP_SUBTITLE

class LoginDialog(QDialog):
    login_successful = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{APP_NAME} - Autentikasi Pengguna")
        self.setFixedSize(460, 580)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(18)

        # Header Section
        header_layout = QVBoxLayout()
        header_layout.setAlignment(Qt.AlignCenter)

        title_lbl = QLabel(f"🛡️ {APP_NAME}")
        title_lbl.setObjectName("TitleLabel")
        title_lbl.setAlignment(Qt.AlignCenter)
        title_lbl.setStyleSheet("font-size: 26px; font-weight: bold; color: #38bdf8;")

        sub_lbl = QLabel(APP_SUBTITLE)
        sub_lbl.setObjectName("SubtitleLabel")
        sub_lbl.setAlignment(Qt.AlignCenter)

        header_layout.addWidget(title_lbl)
        header_layout.addWidget(sub_lbl)
        main_layout.addLayout(header_layout)

        # Main Card Frame
        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        card_layout.setSpacing(14)

        # Username Input
        user_lbl = QLabel("Username")
        user_lbl.setStyleSheet("font-weight: 600; color: #94a3b8;")
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Masukkan username Anda")
        card_layout.addWidget(user_lbl)
        card_layout.addWidget(self.user_input)

        # Password Input
        pwd_lbl = QLabel("Master Password")
        pwd_lbl.setStyleSheet("font-weight: 600; color: #94a3b8;")
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setPlaceholderText("Masukkan master password")
        self.pwd_input.returnPressed.connect(self._handle_login)
        card_layout.addWidget(pwd_lbl)
        card_layout.addWidget(self.pwd_input)

        # Hardware Multi-Factor Checkboxes
        mfa_layout = QVBoxLayout()
        mfa_layout.setSpacing(6)

        self.cb_biometric = QCheckBox("Gunakan Verifikasi Biometrik (Face Recognition Webcam)")
        self.cb_biometric.setStyleSheet("color: #cbd5e1;")
        mfa_layout.addWidget(self.cb_biometric)

        self.cb_dongle = QCheckBox("Gunakan Verifikasi USB Security Dongle")
        self.cb_dongle.setStyleSheet("color: #cbd5e1;")
        mfa_layout.addWidget(self.cb_dongle)

        card_layout.addLayout(mfa_layout)

        # Hardware Status Banner
        self.hw_status_lbl = QLabel(self._get_hardware_summary())
        self.hw_status_lbl.setWordWrap(True)
        self.hw_status_lbl.setStyleSheet(
            "background-color: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 8px; font-size: 11px; color: #94a3b8;"
        )
        card_layout.addWidget(self.hw_status_lbl)

        # Login Button
        self.btn_login = QPushButton("Masuk ke Vault")
        self.btn_login.setObjectName("PrimaryBtn")
        self.btn_login.setFixedHeight(42)
        self.btn_login.clicked.connect(self._handle_login)
        card_layout.addWidget(self.btn_login)

        main_layout.addWidget(card)

        # Register Footer Link
        footer_layout = QHBoxLayout()
        footer_layout.setAlignment(Qt.AlignCenter)
        reg_text = QLabel("Belum memiliki akun?")
        reg_text.setStyleSheet("color: #94a3b8;")
        self.btn_open_reg = QPushButton("Daftar Akun Baru")
        self.btn_open_reg.setStyleSheet("background: transparent; color: #38bdf8; font-weight: bold; border: none; text-decoration: underline;")
        self.btn_open_reg.clicked.connect(self._open_register_dialog)

        footer_layout.addWidget(reg_text)
        footer_layout.addWidget(self.btn_open_reg)
        main_layout.addLayout(footer_layout)

    def _get_hardware_summary(self) -> str:
        bio_info = BiometricAuth.check_availability()
        dongles = USBDongleAuth.list_connected_usb_drives()
        
        bio_str = "Webcam Face Scan Siap" if bio_info["available"] else "Tidak Terdeteksi"
        usb_count = len(dongles)
        
        return f"Hardware: Biometrik={bio_str} | USB Drives/Tokens={usb_count}"

    def _handle_login(self):
        username = self.user_input.text().strip()
        password = self.pwd_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Validasi Gagal", "Username dan password wajib diisi.")
            return

        self.btn_login.setEnabled(False)
        self.btn_login.setText("Memverifikasi...")

        try:
            success, msg = AuthService.login(
                username=username,
                password=password,
                require_biometric=self.cb_biometric.isChecked(),
                require_dongle=self.cb_dongle.isChecked(),
                parent_window=self
            )

            if success:
                from core.auth import session
                self.login_successful.emit(session.get_user())
                self.accept()
            else:
                QMessageBox.critical(self, "Login Gagal", msg)
        except Exception as e:
            QMessageBox.critical(self, "Error Sistem", f"Kesalahan internal: {str(e)}")
        finally:
            self.btn_login.setEnabled(True)
            self.btn_login.setText("Masuk ke Vault")

    def _open_register_dialog(self):
        from ui.register import RegisterDialog
        dlg = RegisterDialog(self)
        if dlg.exec():
            # Pre-fill username from registration
            self.user_input.setText(dlg.registered_username)
            self.pwd_input.setFocus()
