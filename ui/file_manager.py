"""
SecureVault - UI: File Encryption Manager (ChaCha20-Poly1305)
Provides chunked authenticated file encryption and decryption for all file types
(PDF, DOCX, TXT, ZIP, Images, etc.), SHA-256 bit-for-bit fidelity check, and progress indicators.
"""

from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QMessageBox, QFrame, QSplitter
)
from PySide6.QtCore import Qt
from core.auth import session
from services.file_service import FileService
from crypto.hashing import HashManager

class FileManagerView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_file_path = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        header = QVBoxLayout()
        title = QLabel("🗄️ Enkripsi & Proteksi File (ChaCha20-Poly1305 AEAD)")
        title.setObjectName("TitleLabel")
        desc = QLabel(
            "Mengamankan dokumen dan file dengan cipher stream ChaCha20-Poly1305 berperforma tinggi. "
            "Mendukung file besar secara aman melalui chunked authenticated streaming dan penjaminan integritas SHA-256."
        )
        desc.setObjectName("SubtitleLabel")
        desc.setWordWrap(True)
        header.addWidget(title)
        header.addWidget(desc)
        layout.addLayout(header)

        # Top Control Card: File Upload & Action
        top_card = QFrame()
        top_card.setObjectName("Card")
        tc_layout = QVBoxLayout(top_card)
        tc_layout.setContentsMargins(18, 16, 18, 16)
        tc_layout.setSpacing(12)

        file_pick_layout = QHBoxLayout()
        self.btn_select_file = QPushButton("📂 Pilih File dari Komputer...")
        self.btn_select_file.setObjectName("SecondaryBtn")
        self.btn_select_file.clicked.connect(self._select_file)

        self.lbl_selected_file = QLabel("Belum ada file yang dipilih.")
        self.lbl_selected_file.setStyleSheet("color: #94a3b8; font-style: italic;")

        self.btn_encrypt_file = QPushButton("🔒 Enkripsi File ke Vault")
        self.btn_encrypt_file.setObjectName("PrimaryBtn")
        self.btn_encrypt_file.setEnabled(False)
        self.btn_encrypt_file.clicked.connect(self._encrypt_file)

        file_pick_layout.addWidget(self.btn_select_file)
        file_pick_layout.addWidget(self.lbl_selected_file, stretch=1)
        file_pick_layout.addWidget(self.btn_encrypt_file)
        tc_layout.addLayout(file_pick_layout)

        # Selected File Metadata details
        self.lbl_file_meta = QLabel("")
        self.lbl_file_meta.setStyleSheet("font-size: 11px; color: #38bdf8;")
        tc_layout.addWidget(self.lbl_file_meta)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(12)
        self.progress_bar.setVisible(False)
        tc_layout.addWidget(self.progress_bar)

        layout.addWidget(top_card)

        # Vault Encrypted Files Table Card
        table_card = QFrame()
        table_card.setObjectName("Card")
        tb_layout = QVBoxLayout(table_card)
        tb_layout.setContentsMargins(18, 16, 18, 16)
        tb_layout.setSpacing(12)

        tb_header = QHBoxLayout()
        tb_title = QLabel("📦 File Terenkripsi dalam Vault")
        tb_title.setObjectName("SectionHeader")
        tb_header.addWidget(tb_title)
        tb_header.addStretch()

        self.btn_decrypt_selected = QPushButton("🔓 Dekripsi & Unduh File Terpilih")
        self.btn_decrypt_selected.setObjectName("SuccessBtn")
        self.btn_decrypt_selected.clicked.connect(self._decrypt_selected_file)
        tb_header.addWidget(self.btn_decrypt_selected)

        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setObjectName("SecondaryBtn")
        self.btn_refresh.clicked.connect(self.refresh_table)
        tb_header.addWidget(self.btn_refresh)
        tb_layout.addLayout(tb_header)

        self.file_table = QTableWidget()
        self.file_table.setColumnCount(6)
        self.file_table.setHorizontalHeaderLabels(["ID", "Nama File Asli", "Ukuran", "Algoritma", "SHA-256 Checksum", "Waktu Enkripsi"])
        self.file_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.file_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.file_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.file_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.file_table.setSelectionMode(QTableWidget.SingleSelection)
        self.file_table.verticalHeader().setVisible(False)
        tb_layout.addWidget(self.file_table)

        layout.addWidget(table_card, stretch=1)

    def _select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Pilih File untuk Dienkripsi",
            "",
            "Semua File (*.*);;PDF Documents (*.pdf);;Images (*.png *.jpg *.jpeg);;Word Documents (*.docx);;Archives (*.zip *.rar)"
        )
        if file_path:
            p = Path(file_path)
            self.selected_file_path = p
            size_mb = p.stat().st_size / (1024 * 1024)
            sha256 = HashManager.sha256_file(p)

            self.lbl_selected_file.setText(f"{p.name} ({size_mb:.2f} MB)")
            self.lbl_selected_file.setStyleSheet("color: #f8fafc; font-weight: bold;")
            self.lbl_file_meta.setText(f"SHA-256 Asli: {sha256}")
            self.btn_encrypt_file.setEnabled(True)

    def _encrypt_file(self):
        if not self.selected_file_path or not self.selected_file_path.exists():
            QMessageBox.warning(self, "Peringatan", "File yang dipilih tidak ditemukan.")
            return

        user_id = session.get_user_id()
        if not user_id:
            QMessageBox.critical(self, "Error", "Sesi login tidak valid.")
            return

        self.btn_encrypt_file.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        def progress_cb(pct):
            self.progress_bar.setValue(pct)

        try:
            res = FileService.encrypt_and_store_file(
                owner_id=user_id,
                original_file_path=str(self.selected_file_path),
                progress_callback=progress_cb
            )

            QMessageBox.information(
                self,
                "Enkripsi Berhasil",
                f"File '{res['original_name']}' berhasil dienkripsi!\n\n"
                f"• Algoritma: ChaCha20-Poly1305\n"
                f"• SHA-256 Asli: {res['sha256'][:24]}...\n"
                f"• Dicatat pada Blockchain Blok #{res['block_index']}"
            )
            self.refresh_table()
        except Exception as e:
            QMessageBox.critical(self, "Enkripsi Gagal", f"Terjadi kesalahan saat mengenkripsi: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)
            self.btn_encrypt_file.setEnabled(True)

    def _decrypt_selected_file(self):
        selected_row = self.file_table.currentRow()
        if selected_row < 0:
            QMessageBox.warning(self, "Peringatan", "Silakan pilih baris file pada tabel yang ingin didekripsi.")
            return

        file_id = int(self.file_table.item(selected_row, 0).text())
        file_name = self.file_table.item(selected_row, 1).text()
        user_id = session.get_user_id()

        target_dir = QFileDialog.getExistingDirectory(self, "Pilih Folder Penyimpanan File Hasil Dekripsi")
        if not target_dir:
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        def progress_cb(pct):
            self.progress_bar.setValue(pct)

        try:
            res = FileService.decrypt_stored_file(
                owner_id=user_id,
                file_id=file_id,
                target_dir=target_dir,
                progress_callback=progress_cb
            )

            QMessageBox.information(
                self,
                "Dekripsi & Verifikasi Berhasil",
                f"File '{file_name}' berhasil didekripsi!\n\n"
                f"• Lokasi: {res['decrypted_path']}\n"
                f"• SHA-256 Verifikasi: {res['sha256'][:24]}...\n"
                f"• Integritas: Bit-for-bit IDENTIK dengan file asli!"
            )
        except Exception as e:
            QMessageBox.critical(self, "Dekripsi Gagal", f"Verifikasi integritas atau dekripsi gagal: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)

    def refresh_table(self):
        user_id = session.get_user_id()
        if not user_id:
            return

        files = FileService.get_user_files(user_id)
        self.file_table.setRowCount(len(files))

        for idx, f in enumerate(files):
            self.file_table.setItem(idx, 0, QTableWidgetItem(str(f["id"])))
            self.file_table.setItem(idx, 1, QTableWidgetItem(f["original_name"]))
            
            size_kb = f["file_size_bytes"] / 1024
            size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb/1024:.2f} MB"
            self.file_table.setItem(idx, 2, QTableWidgetItem(size_str))
            
            self.file_table.setItem(idx, 3, QTableWidgetItem(f["algorithm"]))
            self.file_table.setItem(idx, 4, QTableWidgetItem(f["sha256_hash"]))
            self.file_table.setItem(idx, 5, QTableWidgetItem(str(f["created_at"])))
