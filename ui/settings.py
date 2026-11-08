"""
SecureVault - UI: Settings & Hardware Security Manager
Manages MFA policies, Windows Hello biometric testing, USB Security Dongle pairing,
and cryptographic parameter inspection.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QComboBox, QMessageBox, QFrame, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PySide6.QtCore import Qt
from core.auth import session
from services.auth_service import AuthService
from hardware.biometric import BiometricAuth
from hardware.dongle import USBDongleAuth
from config.settings import DEV_MODE

class SettingsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        header = QVBoxLayout()
        title = QLabel("⚙️ Pengaturan Keamanan & Perangkat Keras")
        title.setObjectName("TitleLabel")
        desc = QLabel(
            "Konfigurasi kebijakan Multi-Factor Authentication (MFA), daftarkan USB Security Dongle fisik, "
            "dan lakukan uji verifikasi sensor Windows Hello."
        )
        desc.setObjectName("SubtitleLabel")
        desc.setWordWrap(True)
        header.addWidget(title)
        header.addWidget(desc)
        layout.addLayout(header)

        # 1. Multi-Factor Authentication (MFA) Policies Card
        mfa_card = QFrame()
        mfa_card.setObjectName("Card")
        mc_layout = QVBoxLayout(mfa_card)
        mc_layout.setContentsMargins(18, 16, 18, 16)
        mc_layout.setSpacing(12)

        mc_title = QLabel("🛡️ Kebijakan Autentikasi Tambahan (MFA Requirements)")
        mc_title.setObjectName("SectionHeader")
        mc_layout.addWidget(mc_title)

        self.cb_require_biometric = QCheckBox("Wajibkan Autentikasi Windows Hello (Biometrik Face/Fingerprint/PIN) saat Login")
        self.cb_require_biometric.setStyleSheet("color: #e2e8f0; font-size: 13px;")
        mc_layout.addWidget(self.cb_require_biometric)

        self.cb_require_dongle = QCheckBox("Wajibkan USB Security Dongle terdaftar ditancapkan saat Login")
        self.cb_require_dongle.setStyleSheet("color: #e2e8f0; font-size: 13px;")
        mc_layout.addWidget(self.cb_require_dongle)

        btn_save_mfa = QPushButton("💾 Simpan Pengaturan Kebijakan MFA")
        btn_save_mfa.setObjectName("PrimaryBtn")
        btn_save_mfa.clicked.connect(self._save_mfa_settings)
        mc_layout.addWidget(btn_save_mfa, alignment=Qt.AlignLeft)

        layout.addWidget(mfa_card)

        # 2. Hardware Management: USB Dongles
        dongle_card = QFrame()
        dongle_card.setObjectName("Card")
        dc_layout = QVBoxLayout(dongle_card)
        dc_layout.setContentsMargins(18, 16, 18, 16)
        dc_layout.setSpacing(12)

        dc_title = QLabel("🔑 Pendaftaran USB Security Dongle")
        dc_title.setObjectName("SectionHeader")
        dc_layout.addWidget(dc_title)

        h_pair = QHBoxLayout()
        h_pair.addWidget(QLabel("Pilih Drive USB:"))
        self.combo_drives = QComboBox()
        self.combo_drives.setMinimumWidth(260)
        h_pair.addWidget(self.combo_drives)

        self.btn_scan_usb = QPushButton("🔍 Scan USB")
        self.btn_scan_usb.setObjectName("SecondaryBtn")
        self.btn_scan_usb.clicked.connect(self._scan_usb_devices)
        h_pair.addWidget(self.btn_scan_usb)

        self.btn_register_dongle = QPushButton("⚡ Pasangkan USB Ini sebagai Dongle")
        self.btn_register_dongle.setObjectName("SuccessBtn")
        self.btn_register_dongle.clicked.connect(self._register_usb)
        h_pair.addWidget(self.btn_register_dongle)
        h_pair.addStretch()

        dc_layout.addLayout(h_pair)

        # Registered Dongles Table
        dc_layout.addWidget(QLabel("Daftar USB Dongle Terdaftar untuk Akun Ini:"))
        self.dongle_table = QTableWidget()
        self.dongle_table.setColumnCount(3)
        self.dongle_table.setHorizontalHeaderLabels(["Label Perangkat", "Fingerprint Token (SHA-256)", "Waktu Registrasi"])
        self.dongle_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.dongle_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.dongle_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.dongle_table.verticalHeader().setVisible(False)
        self.dongle_table.setFixedHeight(120)
        dc_layout.addWidget(self.dongle_table)

        layout.addWidget(dongle_card)

        # 3. Windows Hello Test Card
        hello_card = QFrame()
        hello_card.setObjectName("Card")
        hc_layout = QVBoxLayout(hello_card)
        hc_layout.setContentsMargins(18, 16, 18, 16)
        hc_layout.setSpacing(10)

        hc_title = QLabel("👤 Windows Hello Biometric Test")
        hc_title.setObjectName("SectionHeader")
        hc_layout.addWidget(hc_title)

        self.lbl_hello_status = QLabel("Status Windows Hello: Memeriksa...")
        self.lbl_hello_status.setStyleSheet("color: #94a3b8;")
        hc_layout.addWidget(self.lbl_hello_status)

        self.btn_test_hello = QPushButton("🧪 Tes Prompt Autentikasi Windows Hello Sekarang")
        self.btn_test_hello.setObjectName("SecondaryBtn")
        self.btn_test_hello.clicked.connect(self._test_windows_hello)
        hc_layout.addWidget(self.btn_test_hello, alignment=Qt.AlignLeft)

        layout.addWidget(hello_card)
        layout.addStretch()

    def load_user_settings(self):
        user_id = session.get_user_id()
        if not user_id:
            return

        settings = AuthService.get_user_security_settings(user_id)
        self.cb_require_biometric.setChecked(settings["biometric_enabled"])
        self.cb_require_dongle.setChecked(settings["dongle_enabled"])

        # Populate dongle table
        dongles = settings["registered_dongles"]
        self.dongle_table.setRowCount(len(dongles))
        for i, d in enumerate(dongles):
            self.dongle_table.setItem(i, 0, QTableWidgetItem(d["dongle_label"] or "USB Key"))
            self.dongle_table.setItem(i, 1, QTableWidgetItem(d["dongle_fingerprint"]))
            self.dongle_table.setItem(i, 2, QTableWidgetItem(str(d["registered_at"])))

        # Update Windows Hello check
        bio = BiometricAuth.check_availability()
        self.lbl_hello_status.setText(f"Status Hardware: {bio['message']} {'[DEV MODE ON]' if DEV_MODE else ''}")

        self._scan_usb_devices()

    def _scan_usb_devices(self):
        self.combo_drives.clear()
        drives = USBDongleAuth.list_connected_usb_drives()
        for d in drives:
            self.combo_drives.addItem(f"{d['label']} - Serial: {d['serial']}", d["drive"])

    def _register_usb(self):
        drive_path = self.combo_drives.currentData()
        if not drive_path:
            QMessageBox.warning(self, "Peringatan", "Tidak ada drive USB yang dipilih.")
            return

        user_id = session.get_user_id()
        success, msg = AuthService.register_usb_dongle(user_id, drive_path, label=f"Dongle ({drive_path})")
        if success:
            QMessageBox.information(self, "Registrasi Dongle Berhasil", msg)
            self.load_user_settings()
        else:
            QMessageBox.critical(self, "Gagal", msg)

    def _save_mfa_settings(self):
        user_id = session.get_user_id()
        if not user_id:
            return

        AuthService.update_security_settings(
            user_id=user_id,
            biometric_enabled=self.cb_require_biometric.isChecked(),
            dongle_enabled=self.cb_require_dongle.isChecked()
        )
        QMessageBox.information(self, "Pengaturan Disimpan", "Kebijakan autentikasi MFA berhasil diperbarui!")

    def _test_windows_hello(self):
        ok, msg = BiometricAuth.verify_biometric(prompt_message="Uji Verifikasi Biometrik Windows Hello SecureVault")
        if ok:
            QMessageBox.information(self, "Verifikasi Sukses", f"✅ {msg}")
        else:
            QMessageBox.warning(self, "Verifikasi Gagal", f"❌ {msg}")
