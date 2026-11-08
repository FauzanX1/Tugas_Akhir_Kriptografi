"""
SecureVault - UI: Super-Encryption (Text Cryptography)
Multi-stage encryption combining classical Vigenère Cipher and modern AES-256-GCM.
Displays intermediate stages, unique nonces, authentication tags, and tamper detection.
"""

import os
import hashlib
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QTextEdit, QPushButton, QMessageBox, QFrame, QSplitter,
    QApplication
)
from PySide6.QtCore import Qt
from crypto.vigenere import VigenereCipher
from crypto.aes import AES256GCMCipher
from core.key_manager import key_manager
from core.auth import session

class TextCryptoView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        # Header
        header = QVBoxLayout()
        title = QLabel("🔐 Super-Encryption: Teks Multilayer (Vigenère + AES-256-GCM)")
        title.setObjectName("TitleLabel")
        desc = QLabel(
            "Menggabungkan cipher substitusi polialfabetik klasik (Vigenère) dengan cipher modern terautentikasi "
            "(AES-256 Galois/Counter Mode). Menampilkan hasil transparan setiap tahapan enkripsi dan dekripsi."
        )
        desc.setObjectName("SubtitleLabel")
        desc.setWordWrap(True)
        header.addWidget(title)
        header.addWidget(desc)
        main_layout.addLayout(header)

        # Educational Warning Banner
        warn_frame = QFrame()
        warn_frame.setObjectName("Card")
        warn_frame.setStyleSheet("background-color: rgba(245, 158, 11, 0.08); border: 1px solid #d97706; border-radius: 8px;")
        warn_layout = QHBoxLayout(warn_frame)
        warn_layout.setContentsMargins(12, 10, 12, 10)
        warn_lbl = QLabel(
            "⚠️ Catatan Teori Kriptografi: Vigenère Cipher rentan terhadap Analisis Frekuensi dan Uji Kasiski. "
            "Algoritma ini diimplementasikan khusus untuk tujuan analisis akademis dan demonstrasi pertahanan berlapis, "
            "sedangkan jaminan kerahasiaan dan integritas matematis utama disediakan oleh AES-256-GCM."
        )
        warn_lbl.setStyleSheet("color: #fbbf24; font-size: 12px;")
        warn_lbl.setWordWrap(True)
        warn_layout.addWidget(warn_lbl)
        main_layout.addWidget(warn_frame)

        # Key Inputs Card
        key_card = QFrame()
        key_card.setObjectName("Card")
        kc_layout = QHBoxLayout(key_card)
        kc_layout.setContentsMargins(16, 14, 16, 14)
        kc_layout.setSpacing(16)

        # Vigenere Key
        v_layout = QVBoxLayout()
        v_lbl = QLabel("Kunci Vigenère (Alfabetik):")
        v_lbl.setStyleSheet("font-weight: 600; color: #38bdf8;")
        self.vigenere_key_input = QLineEdit()
        self.vigenere_key_input.setPlaceholderText("Contoh: SECRETKEY")
        self.vigenere_key_input.setText("KRIPTOGRAFI")
        v_layout.addWidget(v_lbl)
        v_layout.addWidget(self.vigenere_key_input)
        kc_layout.addLayout(v_layout, stretch=1)

        # AES-256 Key
        aes_layout = QVBoxLayout()
        aes_lbl = QLabel("Kunci Rahasia AES-256 (256-bit Hex / Passphrase):")
        aes_lbl.setStyleSheet("font-weight: 600; color: #38bdf8;")
        h_aes = QHBoxLayout()
        self.aes_key_input = QLineEdit()
        self.aes_key_input.setText(os.urandom(32).hex())
        self.btn_gen_aes = QPushButton("🎲 Generate Kunci Baru")
        self.btn_gen_aes.setObjectName("SecondaryBtn")
        self.btn_gen_aes.clicked.connect(self._generate_new_aes_key)
        h_aes.addWidget(self.aes_key_input)
        h_aes.addWidget(self.btn_gen_aes)
        aes_layout.addWidget(aes_lbl)
        aes_layout.addLayout(h_aes)
        kc_layout.addLayout(aes_layout, stretch=2)

        main_layout.addWidget(key_card)

        # Workspace: Splitter Left (Plaintext & Controls) and Right (Inspection Stages & Ciphertext)
        splitter = QSplitter(Qt.Horizontal)

        # LEFT PANEL: Inputs & Decrypt Action
        left_panel = QFrame()
        left_panel.setObjectName("Card")
        lp_layout = QVBoxLayout(left_panel)
        lp_layout.setContentsMargins(16, 16, 16, 16)
        lp_layout.setSpacing(12)

        lp_title = QLabel("1. Input Plaintext / Ciphertext")
        lp_title.setObjectName("SectionHeader")
        lp_layout.addWidget(lp_title)

        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Ketikkan pesan rahasia yang ingin dienkripsi di sini...")
        self.input_text.setText("Selamat datang di SecureVault. Pesan rahasia ini dilindungi oleh Vigenere + AES-256-GCM!")
        lp_layout.addWidget(self.input_text)

        # Action Buttons
        btn_layout = QHBoxLayout()
        self.btn_encrypt = QPushButton("🔒 Jalankan Super-Enkripsi")
        self.btn_encrypt.setObjectName("PrimaryBtn")
        self.btn_encrypt.setFixedHeight(40)
        self.btn_encrypt.clicked.connect(self._run_super_encryption)

        self.btn_decrypt = QPushButton("🔓 Jalankan Super-Dekripsi")
        self.btn_decrypt.setObjectName("SuccessBtn")
        self.btn_decrypt.setFixedHeight(40)
        self.btn_decrypt.clicked.connect(self._run_super_decryption)

        btn_layout.addWidget(self.btn_encrypt)
        btn_layout.addWidget(self.btn_decrypt)
        lp_layout.addLayout(btn_layout)

        splitter.addWidget(left_panel)

        # RIGHT PANEL: Multistage Results & Inspection
        right_panel = QFrame()
        right_panel.setObjectName("Card")
        rp_layout = QVBoxLayout(right_panel)
        rp_layout.setContentsMargins(16, 16, 16, 16)
        rp_layout.setSpacing(12)

        rp_title = QLabel("2. Hasil Inspeksi Tahapan (Pipeline Cryptography)")
        rp_title.setObjectName("SectionHeader")
        rp_layout.addWidget(rp_title)

        # Stage 1: Vigenere Intermediate
        stage1_lbl = QLabel("Tahap 1: Hasil Cipher Klasik (Vigenère Output):")
        stage1_lbl.setStyleSheet("color: #94a3b8; font-weight: 600; font-size: 11px;")
        self.stage1_output = QLineEdit()
        self.stage1_output.setReadOnly(True)
        self.stage1_output.setStyleSheet("background-color: #0b1120; color: #a5f3fc; font-family: monospace;")
        rp_layout.addWidget(stage1_lbl)
        rp_layout.addWidget(self.stage1_output)

        # Stage 2: AES-256-GCM Components
        meta_layout = QHBoxLayout()
        
        v_nonce = QVBoxLayout()
        v_nonce.addWidget(QLabel("AES-256 Nonce (12 Bytes Hex):"))
        self.nonce_output = QLineEdit()
        self.nonce_output.setReadOnly(True)
        self.nonce_output.setStyleSheet("background-color: #0b1120; color: #fde047; font-family: monospace; font-size: 11px;")
        v_nonce.addWidget(self.nonce_output)
        meta_layout.addLayout(v_nonce)

        v_tag = QVBoxLayout()
        v_tag.addWidget(QLabel("AES-GCM Auth Tag (16 Bytes Hex):"))
        self.tag_output = QLineEdit()
        self.tag_output.setReadOnly(True)
        self.tag_output.setStyleSheet("background-color: #0b1120; color: #4ade80; font-family: monospace; font-size: 11px;")
        v_tag.addWidget(self.tag_output)
        meta_layout.addLayout(v_tag)

        rp_layout.addLayout(meta_layout)

        # Stage 3: Final Combined Ciphertext Bundle
        stage2_lbl = QLabel("Tahap 2: Ciphertext Akhir (Base64 Bundled Payload):")
        stage2_lbl.setStyleSheet("color: #38bdf8; font-weight: bold;")
        rp_layout.addWidget(stage2_lbl)

        self.final_output = QTextEdit()
        self.final_output.setReadOnly(True)
        self.final_output.setStyleSheet("background-color: #0b1120; color: #f8fafc; font-family: monospace;")
        rp_layout.addWidget(self.final_output)

        # Copy & Decrypted Plaintext Result
        res_actions = QHBoxLayout()
        self.btn_copy = QPushButton("📋 Salin Ciphertext")
        self.btn_copy.setObjectName("SecondaryBtn")
        self.btn_copy.clicked.connect(self._copy_ciphertext)
        
        self.btn_fill_input = QPushButton("📥 Masukkan ke Input Dekripsi")
        self.btn_fill_input.setObjectName("SecondaryBtn")
        self.btn_fill_input.clicked.connect(self._fill_input_with_ciphertext)

        res_actions.addWidget(self.btn_copy)
        res_actions.addWidget(self.btn_fill_input)
        rp_layout.addLayout(res_actions)

        splitter.addWidget(right_panel)
        main_layout.addWidget(splitter, stretch=1)

    def _generate_new_aes_key(self):
        self.aes_key_input.setText(os.urandom(32).hex())

    def _get_aes_key_bytes(self) -> bytes:
        raw = self.aes_key_input.text().strip()
        try:
            if len(raw) == 64:
                return bytes.fromhex(raw)
            else:
                return hashlib.sha256(raw.encode("utf-8")).digest()
        except Exception:
            return hashlib.sha256(raw.encode("utf-8")).digest()

    def _run_super_encryption(self):
        plaintext = self.input_text.toPlainText().strip()
        v_key = self.vigenere_key_input.text().strip()
        if not plaintext:
            QMessageBox.warning(self, "Peringatan", "Plaintext tidak boleh kosong.")
            return
        if not v_key:
            QMessageBox.warning(self, "Peringatan", "Kunci Vigenère wajib diisi.")
            return

        try:
            # Stage 1: Vigenère Classical Encryption
            vigenere_encrypted = VigenereCipher.encrypt(plaintext, v_key)
            self.stage1_output.setText(vigenere_encrypted)

            # Stage 2: AES-256-GCM Modern Authenticated Encryption
            aes_key = self._get_aes_key_bytes()
            enc_result = AES256GCMCipher.encrypt(vigenere_encrypted, aes_key)

            # Display components
            import base64
            nonce_bytes = base64.b64decode(enc_result["nonce"])
            tag_bytes = base64.b64decode(enc_result["tag"])

            self.nonce_output.setText(nonce_bytes.hex())
            self.tag_output.setText(tag_bytes.hex())
            self.final_output.setPlainText(enc_result["bundle"])

            QMessageBox.information(
                self,
                "Super-Enkripsi Berhasil",
                "Pesan berhasil melalui 2 tahapan pengamanan:\n"
                "1. Vigenère Cipher (Substitusi)\n"
                "2. AES-256-GCM (Enkripsi Modern + Tag Autentikasi 128-bit)"
            )
        except Exception as e:
            QMessageBox.critical(self, "Enkripsi Gagal", f"Terjadi kesalahan: {str(e)}")

    def _run_super_decryption(self):
        bundle_text = self.input_text.toPlainText().strip()
        v_key = self.vigenere_key_input.text().strip()

        if not bundle_text:
            QMessageBox.warning(self, "Peringatan", "Masukkan ciphertext (Base64 bundle) pada kotak input.")
            return

        try:
            # Stage 1: AES-256-GCM Authenticated Decryption
            aes_key = self._get_aes_key_bytes()
            decrypted_stage1_bytes = AES256GCMCipher.decrypt(bundle_text, aes_key)
            decrypted_stage1_str = decrypted_stage1_bytes.decode("utf-8")
            self.stage1_output.setText(decrypted_stage1_str)

            # Stage 2: Vigenère Decryption
            final_plaintext = VigenereCipher.decrypt(decrypted_stage1_str, v_key)

            self.final_output.setPlainText(final_plaintext)
            QMessageBox.information(
                self,
                "Super-Dekripsi Berhasil",
                f"Ciphertext berhasil diverifikasi & didekripsi secara utuh!\n\nHasil Plaintext:\n{final_plaintext}"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Dekripsi Gagal",
                f"Kesalahan Integritas atau Kunci Salah:\n{str(e)}"
            )

    def _copy_ciphertext(self):
        text = self.final_output.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Disalin", "Teks berhasil disalin ke clipboard.")

    def _fill_input_with_ciphertext(self):
        text = self.final_output.toPlainText()
        if text:
            self.input_text.setPlainText(text)
