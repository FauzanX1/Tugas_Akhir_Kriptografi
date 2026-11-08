"""
SecureVault - UI: Dashboard View
Displays cryptographic activity summaries, user profile, security posture,
and recent audit logs.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton
)
from PySide6.QtCore import Qt
from config.database import db
from core.auth import session
from hardware.biometric import BiometricAuth
from hardware.dongle import USBDongleAuth

class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        # Title & Welcome Header
        header = QHBoxLayout()
        v_title = QVBoxLayout()
        self.welcome_lbl = QLabel("Dashboard Sistem Keamanan")
        self.welcome_lbl.setObjectName("TitleLabel")
        self.sub_lbl = QLabel("Monitoring status kriptografi, integritas blockchain, dan perangkat keras.")
        self.sub_lbl.setObjectName("SubtitleLabel")
        v_title.addWidget(self.welcome_lbl)
        v_title.addWidget(self.sub_lbl)
        header.addLayout(v_title)
        header.addStretch()

        self.btn_refresh = QPushButton("🔄 Perbarui Data")
        self.btn_refresh.setObjectName("SecondaryBtn")
        self.btn_refresh.clicked.connect(self.refresh_data)
        header.addWidget(self.btn_refresh)
        layout.addLayout(header)

        # 4 Metric Cards Row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(16)

        self.card_files = self._create_metric_card("📁 File Vault", "0 File", "Terenkripsi ChaCha20-Poly1305", "#38bdf8")
        self.card_msgs = self._create_metric_card("💬 Pesan Database", "0 Pesan", "Terenkripsi AES-256-GCM", "#818cf8")
        self.card_stego = self._create_metric_card("🖼️ Steganografi", "0 Gambar", "LSB + Authenticated AEAD", "#34d399")
        self.card_blocks = self._create_metric_card("⛓️ Blockchain Blocks", "0 Blok", "Integritas Aset SHA-256", "#f59e0b")

        cards_layout.addWidget(self.card_files["frame"])
        cards_layout.addWidget(self.card_msgs["frame"])
        cards_layout.addWidget(self.card_stego["frame"])
        cards_layout.addWidget(self.card_blocks["frame"])
        layout.addLayout(cards_layout)

        # Middle Row: Hardware Security Status & Cryptography Overview
        mid_row = QHBoxLayout()
        mid_row.setSpacing(16)

        # Hardware Security Posture Card
        hw_card = QFrame()
        hw_card.setObjectName("Card")
        hw_card_layout = QVBoxLayout(hw_card)
        hw_card_layout.setContentsMargins(18, 18, 18, 18)
        hw_card_layout.setSpacing(12)

        hw_title = QLabel("🛡️ Status Keamanan & Autentikasi Hardware")
        hw_title.setObjectName("SectionHeader")
        hw_card_layout.addWidget(hw_title)

        self.lbl_argon = QLabel("• Password Hashing: Argon2id (RFC 9106, 64MB RAM, 3 Iterasi, Memory-Hard)")
        self.lbl_argon.setStyleSheet("color: #cbd5e1;")
        hw_card_layout.addWidget(self.lbl_argon)

        self.lbl_hello = QLabel("• Windows Hello Biometrik: Memeriksa status...")
        self.lbl_hello.setStyleSheet("color: #cbd5e1;")
        hw_card_layout.addWidget(self.lbl_hello)

        self.lbl_dongle = QLabel("• USB Security Dongle: Memeriksa token...")
        self.lbl_dongle.setStyleSheet("color: #cbd5e1;")
        hw_card_layout.addWidget(self.lbl_dongle)

        self.lbl_cipher = QLabel("• Algoritma Aktif: Vigenère (Klasik) | AES-256-GCM | ChaCha20-Poly1305 | SHA-256")
        self.lbl_cipher.setStyleSheet("color: #38bdf8; font-weight: 500;")
        hw_card_layout.addWidget(self.lbl_cipher)

        mid_row.addWidget(hw_card, stretch=2)
        layout.addLayout(mid_row)

        # Bottom Section: Recent Activity Logs Table
        table_card = QFrame()
        table_card.setObjectName("Card")
        t_layout = QVBoxLayout(table_card)
        t_layout.setContentsMargins(18, 18, 18, 18)
        t_layout.setSpacing(12)

        t_title = QLabel("📋 Log Aktivitas Keamanan Terakhir")
        t_title.setObjectName("SectionHeader")
        t_layout.addWidget(t_title)

        self.log_table = QTableWidget()
        self.log_table.setColumnCount(4)
        self.log_table.setHorizontalHeaderLabels(["Waktu", "Aktivitas", "Status", "Rincian"])
        self.log_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.log_table.verticalHeader().setVisible(False)
        self.log_table.setMinimumHeight(200)
        t_layout.addWidget(self.log_table)

        layout.addWidget(table_card, stretch=1)

    def _create_metric_card(self, title: str, count: str, subtitle: str, color_hex: str) -> dict:
        frame = QFrame()
        frame.setObjectName("Card")
        frame.setStyleSheet(f"QFrame#Card {{ border-left: 4px solid {color_hex}; }}")
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(16, 16, 16, 16)
        fl.setSpacing(6)

        t_lbl = QLabel(title)
        t_lbl.setStyleSheet("color: #94a3b8; font-weight: 600; font-size: 12px;")
        val_lbl = QLabel(count)
        val_lbl.setStyleSheet(f"color: {color_hex}; font-size: 22px; font-weight: bold;")
        s_lbl = QLabel(subtitle)
        s_lbl.setStyleSheet("color: #64748b; font-size: 11px;")

        fl.addWidget(t_lbl)
        fl.addWidget(val_lbl)
        fl.addWidget(s_lbl)
        return {"frame": frame, "val_lbl": val_lbl}

    def refresh_data(self):
        user = session.get_user()
        if user:
            name = user.get("full_name") or user.get("username")
            self.welcome_lbl.setText(f"Selamat Datang, {name} 👋")

        # Query metrics from database
        try:
            files_cnt = db.fetch_one("SELECT COUNT(*) as cnt FROM files")["cnt"]
            msgs_cnt = db.fetch_one("SELECT COUNT(*) as cnt FROM messages")["cnt"]
            stego_cnt = db.fetch_one("SELECT COUNT(*) as cnt FROM steganography")["cnt"]
            blocks_cnt = db.fetch_one("SELECT COUNT(*) as cnt FROM blockchain")["cnt"]

            self.card_files["val_lbl"].setText(f"{files_cnt} File")
            self.card_msgs["val_lbl"].setText(f"{msgs_cnt} Pesan")
            self.card_stego["val_lbl"].setText(f"{stego_cnt} Gambar")
            self.card_blocks["val_lbl"].setText(f"{blocks_cnt} Blok")

            # Hardware status
            bio = BiometricAuth.check_availability()
            user_id = session.get_user_id()
            face_tpl = BiometricAuth.get_user_face_template(user_id) if user_id else None
            face_status_str = "Wajah Terdaftar" if face_tpl is not None else "Wajah Belum Terdaftar"
            self.lbl_hello.setText(f"• Biometrik (Face Recognition): {bio['message']} ({face_status_str})")

            usb_list = USBDongleAuth.list_connected_usb_drives()
            self.lbl_dongle.setText(f"• USB Security Dongle: Terdeteksi {len(usb_list)} storage device/token terhubung.")

            # Load recent logs
            logs = db.fetch_all("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 15")
            self.log_table.setRowCount(len(logs))
            for row_idx, log in enumerate(logs):
                self.log_table.setItem(row_idx, 0, QTableWidgetItem(str(log["created_at"])))
                self.log_table.setItem(row_idx, 1, QTableWidgetItem(str(log["action"])))
                
                status_item = QTableWidgetItem(str(log["status"]))
                if log["status"] == "SUCCESS":
                    status_item.setForeground(Qt.green)
                else:
                    status_item.setForeground(Qt.red)
                self.log_table.setItem(row_idx, 2, status_item)
                
                self.log_table.setItem(row_idx, 3, QTableWidgetItem(str(log["details"] or "")))

        except Exception as e:
            print(f"[Dashboard Error] Failed to refresh: {e}")
