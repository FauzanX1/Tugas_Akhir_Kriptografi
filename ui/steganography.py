"""
SecureVault - UI: Image Steganography View (LSB + Authenticated Encryption)
Embeds and extracts encrypted secret messages inside images using Least Significant Bit (LSB).
Features image previews, dynamic capacity meters, and AES-256-GCM encryption before embedding.
"""

from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFileDialog, QTextEdit, QLineEdit, QMessageBox, QFrame,
    QTabWidget, QProgressBar, QSplitter
)
from PySide6.QtGui import QPixmap
from PySide6.QtCore import Qt
from core.auth import session
from services.steganography_service import SteganographyService

class SteganographyView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.encode_image_path = None
        self.decode_image_path = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        header = QVBoxLayout()
        title = QLabel("🖼️ Steganografi Gambar (LSB + AES-256-GCM)")
        title.setObjectName("TitleLabel")
        desc = QLabel(
            "Menyembunyikan pesan rahasia terenkripsi ke dalam piksel gambar (Least Significant Bit). "
            "Pesan dienkripsi terlebih dahulu sebelum disisipkan, divalidasi kapasitasnya, dan disimpan dalam format PNG lossless."
        )
        desc.setObjectName("SubtitleLabel")
        desc.setWordWrap(True)
        header.addWidget(title)
        header.addWidget(desc)
        layout.addLayout(header)

        # Tabs: Encode Secret vs Decode Secret
        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_encode_tab(), "🔒 Sisipkan Pesan (Encode LSB)")
        self.tabs.addTab(self._create_decode_tab(), "🔓 Ekstrak Pesan (Decode LSB)")
        layout.addWidget(self.tabs, stretch=1)

    # ---------------- ENCODE TAB ----------------
    def _create_encode_tab(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Left Column: Image Selection & Preview
        left_card = QFrame()
        left_card.setObjectName("Card")
        lc_layout = QVBoxLayout(left_card)
        lc_layout.setContentsMargins(16, 16, 16, 16)
        lc_layout.setSpacing(10)

        lc_title = QLabel("1. Pilih Gambar Wadah (Cover Image)")
        lc_title.setObjectName("SectionHeader")
        lc_layout.addWidget(lc_title)

        self.btn_select_cover = QPushButton("📂 Pilih Gambar...")
        self.btn_select_cover.setObjectName("SecondaryBtn")
        self.btn_select_cover.clicked.connect(self._select_encode_image)
        lc_layout.addWidget(self.btn_select_cover)

        self.lbl_cover_preview = QLabel("Preview Gambar")
        self.lbl_cover_preview.setAlignment(Qt.AlignCenter)
        self.lbl_cover_preview.setStyleSheet("background-color: #0b1120; border: 1px dashed #334155; border-radius: 8px;")
        self.lbl_cover_preview.setMinimumSize(220, 220)
        lc_layout.addWidget(self.lbl_cover_preview, stretch=1)

        # Capacity Meter
        self.lbl_capacity = QLabel("Kapasitas Penyisipan: -")
        self.lbl_capacity.setStyleSheet("font-weight: 600; color: #38bdf8;")
        lc_layout.addWidget(self.lbl_capacity)

        self.capacity_bar = QProgressBar()
        self.capacity_bar.setValue(0)
        self.capacity_bar.setFixedHeight(12)
        lc_layout.addWidget(self.capacity_bar)

        layout.addWidget(left_card, stretch=1)

        # Right Column: Message Input & Embed Action
        right_card = QFrame()
        right_card.setObjectName("Card")
        rc_layout = QVBoxLayout(right_card)
        rc_layout.setContentsMargins(16, 16, 16, 16)
        rc_layout.setSpacing(10)

        rc_title = QLabel("2. Pesan Rahasia & Kunci Enkripsi")
        rc_title.setObjectName("SectionHeader")
        rc_layout.addWidget(rc_title)

        rc_layout.addWidget(QLabel("Kunci Pengaman Tambahan (Opsional/Passphrase):"))
        self.encode_key_input = QLineEdit()
        self.encode_key_input.setPlaceholderText("Gunakan kunci akun default atau ketik passkey kustom")
        rc_layout.addWidget(self.encode_key_input)

        rc_layout.addWidget(QLabel("Isi Pesan Rahasia:"))
        self.encode_msg_input = QTextEdit()
        self.encode_msg_input.setPlaceholderText("Tuliskan informasi rahasia yang ingin disembunyikan dalam gambar...")
        self.encode_msg_input.textChanged.connect(self._update_capacity_usage)
        rc_layout.addWidget(self.encode_msg_input)

        self.btn_embed = QPushButton("🔒 Enkripsi & Sisipkan ke Gambar (LSB)")
        self.btn_embed.setObjectName("PrimaryBtn")
        self.btn_embed.setFixedHeight(42)
        self.btn_embed.setEnabled(False)
        self.btn_embed.clicked.connect(self._embed_message)
        rc_layout.addWidget(self.btn_embed)

        layout.addWidget(right_card, stretch=1)
        return widget

    def _select_encode_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Pilih Gambar Cover", "", "Images (*.png *.jpg *.jpeg *.bmp)"
        )
        if path:
            self.encode_image_path = Path(path)
            pix = QPixmap(path).scaled(240, 240, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.lbl_cover_preview.setPixmap(pix)

            # Calculate capacity
            cap = SteganographyService.calculate_capacity_bytes(self.encode_image_path)
            self.lbl_capacity.setText(f"Kapasitas Maksimum: {cap:,} Bytes")
            self.btn_embed.setEnabled(True)
            self._update_capacity_usage()

    def _update_capacity_usage(self):
        if not self.encode_image_path:
            return
        msg = self.encode_msg_input.toPlainText().strip()
        msg_len = len(msg.encode("utf-8")) + 64  # estimate AES overhead
        cap = SteganographyService.calculate_capacity_bytes(self.encode_image_path)
        if cap > 0:
            pct = min(100, int((msg_len / cap) * 100))
            self.capacity_bar.setValue(pct)

    def _embed_message(self):
        if not self.encode_image_path:
            return
        secret = self.encode_msg_input.toPlainText().strip()
        if not secret:
            QMessageBox.warning(self, "Peringatan", "Pesan rahasia tidak boleh kosong.")
            return

        user_id = session.get_user_id()
        custom_key = self.encode_key_input.text().strip() or None

        try:
            res = SteganographyService.encode_message_into_image(
                owner_id=user_id,
                image_path=self.encode_image_path,
                secret_text=secret,
                custom_key=custom_key
            )

            QMessageBox.information(
                self,
                "Steganografi Berhasil",
                f"Pesan rahasia berhasil dienkripsi dan disisipkan!\n\n"
                f"• Lokasi Hasil: {res['stego_image_path']}\n"
                f"• Ukuran Payload: {res['payload_size']} Bytes\n"
                f"• Dicatat pada Blockchain Blok #{res['block_index']}\n"
                f"• SHA-256 Stego Image: {res['sha256'][:24]}..."
            )
            self.encode_msg_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Penyisipan Gagal", str(e))

    # ---------------- DECODE TAB ----------------
    def _create_decode_tab(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Left Column: Select Stego Image
        left_card = QFrame()
        left_card.setObjectName("Card")
        lc_layout = QVBoxLayout(left_card)
        lc_layout.setContentsMargins(16, 16, 16, 16)
        lc_layout.setSpacing(10)

        lc_title = QLabel("1. Pilih Gambar Stego")
        lc_title.setObjectName("SectionHeader")
        lc_layout.addWidget(lc_title)

        self.btn_select_stego = QPushButton("📂 Pilih Gambar Stego (PNG)...")
        self.btn_select_stego.setObjectName("SecondaryBtn")
        self.btn_select_stego.clicked.connect(self._select_decode_image)
        lc_layout.addWidget(self.btn_select_stego)

        self.lbl_stego_preview = QLabel("Preview Gambar Stego")
        self.lbl_stego_preview.setAlignment(Qt.AlignCenter)
        self.lbl_stego_preview.setStyleSheet("background-color: #0b1120; border: 1px dashed #334155; border-radius: 8px;")
        self.lbl_stego_preview.setMinimumSize(220, 220)
        lc_layout.addWidget(self.lbl_stego_preview, stretch=1)

        layout.addWidget(left_card, stretch=1)

        # Right Column: Decrypt & Reveal Message
        right_card = QFrame()
        right_card.setObjectName("Card")
        rc_layout = QVBoxLayout(right_card)
        rc_layout.setContentsMargins(16, 16, 16, 16)
        rc_layout.setSpacing(10)

        rc_title = QLabel("2. Kunci & Ekstraksi Plaintext")
        rc_title.setObjectName("SectionHeader")
        rc_layout.addWidget(rc_title)

        rc_layout.addWidget(QLabel("Kunci Pengaman Tambahan (jika diisi saat penyisipan):"))
        self.decode_key_input = QLineEdit()
        self.decode_key_input.setPlaceholderText("Masukkan passkey yang sama")
        rc_layout.addWidget(self.decode_key_input)

        self.btn_extract = QPushButton("🔓 Ekstrak & Dekripsi Pesan (LSB)")
        self.btn_extract.setObjectName("SuccessBtn")
        self.btn_extract.setFixedHeight(42)
        self.btn_extract.setEnabled(False)
        self.btn_extract.clicked.connect(self._extract_message)
        rc_layout.addWidget(self.btn_extract)

        rc_layout.addWidget(QLabel("Hasil Pesan Terdekripsi (Plaintext):"))
        self.decode_msg_output = QTextEdit()
        self.decode_msg_output.setReadOnly(True)
        self.decode_msg_output.setStyleSheet("background-color: #0b1120; color: #4ade80; font-size: 13px;")
        rc_layout.addWidget(self.decode_msg_output)

        layout.addWidget(right_card, stretch=1)
        return widget

    def _select_decode_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Pilih Gambar Stego", "", "Lossless PNG (*.png);;Semua Gambar (*.*)"
        )
        if path:
            self.decode_image_path = Path(path)
            pix = QPixmap(path).scaled(240, 240, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.lbl_stego_preview.setPixmap(pix)
            self.btn_extract.setEnabled(True)

    def _extract_message(self):
        if not self.decode_image_path:
            return

        user_id = session.get_user_id()
        custom_key = self.decode_key_input.text().strip() or None

        try:
            plaintext = SteganographyService.decode_message_from_image(
                owner_id=user_id,
                image_path=self.decode_image_path,
                custom_key=custom_key
            )
            self.decode_msg_output.setPlainText(plaintext)
            QMessageBox.information(
                self,
                "Ekstraksi Berhasil",
                "Pesan rahasia berhasil diekstrak dari piksel LSB dan didekripsi kembali ke bentuk plaintext awal!"
            )
        except Exception as e:
            QMessageBox.critical(self, "Ekstraksi Gagal", f"Gagal mengekstrak/mendekripsi: {str(e)}")
