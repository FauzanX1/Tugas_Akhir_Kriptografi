"""
SecureVault - UI: User Management View
Displays active user cryptographic profile, registered system accounts,
and allows group members to register additional accounts easily.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QMessageBox
)
from PySide6.QtCore import Qt
from core.auth import session
from config.database import db
from ui.register import RegisterDialog

class UserManagementView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        header = QHBoxLayout()
        v_title = QVBoxLayout()
        title = QLabel("👥 Manajemen Pengguna & Profil Kriptografi")
        title.setObjectName("TitleLabel")
        desc = QLabel(
            "Mengelola identitas akun pengguna, melihat profil kriptografis sesi saat ini, "
            "dan mendaftarkan anggota kelompok untuk simulasi komunikasi terenkripsi."
        )
        desc.setObjectName("SubtitleLabel")
        desc.setWordWrap(True)
        v_title.addWidget(title)
        v_title.addWidget(desc)
        header.addLayout(v_title)
        header.addStretch()

        self.btn_new_user = QPushButton("➕ Tambah Pengguna Baru")
        self.btn_new_user.setObjectName("PrimaryBtn")
        self.btn_new_user.clicked.connect(self._open_register_modal)
        header.addWidget(self.btn_new_user)

        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setObjectName("SecondaryBtn")
        self.btn_refresh.clicked.connect(self.refresh_users)
        header.addWidget(self.btn_refresh)

        layout.addLayout(header)

        # Active User Cryptographic Profile Card
        profile_card = QFrame()
        profile_card.setObjectName("CardHighlight")
        pc_layout = QVBoxLayout(profile_card)
        pc_layout.setContentsMargins(18, 16, 18, 16)
        pc_layout.setSpacing(8)

        pc_title = QLabel("🔑 Profil Kriptografi Sesi Aktif")
        pc_title.setObjectName("SectionHeader")
        pc_layout.addWidget(pc_title)

        self.lbl_profile_info = QLabel("Memuat profil...")
        self.lbl_profile_info.setStyleSheet("color: #f8fafc; font-size: 13px;")
        pc_layout.addWidget(self.lbl_profile_info)

        layout.addWidget(profile_card)

        # Registered Users Table Card
        table_card = QFrame()
        table_card.setObjectName("Card")
        tc_layout = QVBoxLayout(table_card)
        tc_layout.setContentsMargins(18, 16, 18, 16)
        tc_layout.setSpacing(12)

        tc_title = QLabel("📋 Daftar Akun Terdaftar dalam Database MySQL")
        tc_title.setObjectName("SectionHeader")
        tc_layout.addWidget(tc_title)

        self.user_table = QTableWidget()
        self.user_table.setColumnCount(5)
        self.user_table.setHorizontalHeaderLabels([
            "ID", "Username", "Nama Lengkap", "Status MFA", "Waktu Registrasi"
        ])
        self.user_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.user_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.user_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.user_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.user_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.user_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.user_table.verticalHeader().setVisible(False)
        tc_layout.addWidget(self.user_table)

        layout.addWidget(table_card, stretch=1)

    def refresh_users(self):
        user = session.get_user()
        if user:
            bio_status = "Aktif" if user.get("biometric_enabled") else "Nonaktif"
            dongle_status = "Aktif" if user.get("dongle_enabled") else "Nonaktif"
            salt_display = user.get("salt", "N/A")
            
            self.lbl_profile_info.setText(
                f"• ID Pengguna: #{user['id']} | Username: <b>{user['username']}</b> | Nama: {user.get('full_name') or '-'}\n"
                f"• Salt Kriptografi: <code>{salt_display}</code> (Unik per akun untuk KDF)\n"
                f"• Status Multi-Factor: Windows Hello: {bio_status} | USB Dongle: {dongle_status}\n"
                f"• Algorithm Pass Hash: Argon2id (Memory: 64MB, Iterations: 3, Threads: 4)"
            )

        users = db.fetch_all("SELECT * FROM users ORDER BY id ASC")
        self.user_table.setRowCount(len(users))

        for idx, u in enumerate(users):
            self.user_table.setItem(idx, 0, QTableWidgetItem(f"#{u['id']}"))
            self.user_table.setItem(idx, 1, QTableWidgetItem(u["username"]))
            self.user_table.setItem(idx, 2, QTableWidgetItem(u.get("full_name") or "-"))

            mfa_parts = []
            if u.get("biometric_enabled"):
                mfa_parts.append("Biometric")
            if u.get("dongle_enabled"):
                mfa_parts.append("Dongle")
            mfa_str = " + ".join(mfa_parts) if mfa_parts else "Password Only"
            self.user_table.setItem(idx, 3, QTableWidgetItem(mfa_str))

            self.user_table.setItem(idx, 4, QTableWidgetItem(str(u["created_at"])))

    def _open_register_modal(self):
        dlg = RegisterDialog(self)
        if dlg.exec():
            self.refresh_users()
