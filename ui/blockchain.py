"""
SecureVault - UI: Blockchain Explorer & Asset Integrity Auditor
Visualizes the SHA-256 blockchain ledger, performs full chain audits,
and provides live tamper detection simulation for academic evaluation.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QFrame, QTextEdit, QInputDialog
)
from PySide6.QtCore import Qt
from services.blockchain_service import BlockchainService
from config.database import db

class BlockchainView(QWidget):
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
        title = QLabel("⛓️ Blockchain Asset Ledger & Audit Integritas (SHA-256)")
        title.setObjectName("TitleLabel")
        desc = QLabel(
            "Buku besar terdistribusi sederhana untuk mencatat dan memverifikasi integritas aset penting "
            "(file terenkripsi, pesan, dan gambar steganografi) dengan hash berantai SHA-256."
        )
        desc.setObjectName("SubtitleLabel")
        desc.setWordWrap(True)
        v_title.addWidget(title)
        v_title.addWidget(desc)
        header.addLayout(v_title)
        header.addStretch()

        self.btn_audit = QPushButton("🔍 Audit Integritas Blockchain")
        self.btn_audit.setObjectName("PrimaryBtn")
        self.btn_audit.clicked.connect(self._audit_blockchain)
        header.addWidget(self.btn_audit)

        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setObjectName("SecondaryBtn")
        self.btn_refresh.clicked.connect(self.refresh_blocks)
        header.addWidget(self.btn_refresh)

        layout.addLayout(header)

        # Blockchain Explorer Table Card
        table_card = QFrame()
        table_card.setObjectName("Card")
        tc_layout = QVBoxLayout(table_card)
        tc_layout.setContentsMargins(18, 16, 18, 16)
        tc_layout.setSpacing(12)

        tc_title = QLabel("📜 Rantai Blok (Block Explorer)")
        tc_title.setObjectName("SectionHeader")
        tc_layout.addWidget(tc_title)

        self.block_table = QTableWidget()
        self.block_table.setColumnCount(7)
        self.block_table.setHorizontalHeaderLabels([
            "Index", "Waktu (Timestamp)", "Nama Aset", "Tipe", "Asset Hash (SHA-256)", "Previous Hash", "Block Hash"
        ])
        self.block_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.block_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.block_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.block_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.block_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.block_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.block_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.block_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.block_table.setSelectionMode(QTableWidget.SingleSelection)
        self.block_table.verticalHeader().setVisible(False)
        self.block_table.itemSelectionChanged.connect(self._on_block_selected)
        tc_layout.addWidget(self.block_table)

        layout.addWidget(table_card, stretch=2)

        # Bottom Inspector Card & Simulation Controls
        bottom_card = QFrame()
        bottom_card.setObjectName("Card")
        bc_layout = QVBoxLayout(bottom_card)
        bc_layout.setContentsMargins(16, 14, 16, 14)
        bc_layout.setSpacing(10)

        bc_header = QHBoxLayout()
        bc_title = QLabel("🔬 Rincian Blok & Simulasi Pengujian Dosen")
        bc_title.setObjectName("SectionHeader")
        bc_header.addWidget(bc_title)
        bc_header.addStretch()

        self.btn_simulate_tamper = QPushButton("🧪 Simulasi Manipulasi Data (Uji Tamper)")
        self.btn_simulate_tamper.setObjectName("DangerBtn")
        self.btn_simulate_tamper.clicked.connect(self._simulate_tamper)
        bc_header.addWidget(self.btn_simulate_tamper)

        self.btn_repair_chain = QPushButton("🛠️ Perbaiki / Pulihkan Hash Blok")
        self.btn_repair_chain.setObjectName("SecondaryBtn")
        self.btn_repair_chain.clicked.connect(self._repair_chain)
        bc_header.addWidget(self.btn_repair_chain)

        bc_layout.addLayout(bc_header)

        self.txt_block_detail = QTextEdit()
        self.txt_block_detail.setReadOnly(True)
        self.txt_block_detail.setStyleSheet("background-color: #0b1120; font-family: monospace; font-size: 11px;")
        self.txt_block_detail.setFixedHeight(120)
        self.txt_block_detail.setPlaceholderText("Pilih blok pada tabel di atas untuk melihat detail struktur data kriptografis.")
        bc_layout.addWidget(self.txt_block_detail)

        layout.addWidget(bottom_card, stretch=1)

    def refresh_blocks(self):
        blocks = BlockchainService.get_all_blocks()
        self.block_table.setRowCount(len(blocks))

        for idx, b in enumerate(blocks):
            self.block_table.setItem(idx, 0, QTableWidgetItem(f"#{b['block_index']}"))
            self.block_table.setItem(idx, 1, QTableWidgetItem(str(b["timestamp"])))
            self.block_table.setItem(idx, 2, QTableWidgetItem(b["asset_name"]))
            self.block_table.setItem(idx, 3, QTableWidgetItem(b["asset_type"]))
            self.block_table.setItem(idx, 4, QTableWidgetItem(b["asset_hash"]))
            self.block_table.setItem(idx, 5, QTableWidgetItem(b["previous_hash"]))
            self.block_table.setItem(idx, 6, QTableWidgetItem(b["block_hash"]))

    def _on_block_selected(self):
        row = self.block_table.currentRow()
        if row < 0:
            return

        blocks = BlockchainService.get_all_blocks()
        if row < len(blocks):
            b = blocks[row]
            detail = (
                f"=== DETAIL BLOCK #{b['block_index']} ===\n"
                f"Timestamp     : {b['timestamp']}\n"
                f"Asset Name    : {b['asset_name']}\n"
                f"Asset Type    : {b['asset_type']}\n"
                f"Asset SHA-256 : {b['asset_hash']}\n"
                f"Previous Hash : {b['previous_hash']}\n"
                f"Proof Nonce   : {b['nonce']}\n"
                f"Block Hash    : {b['block_hash']}\n"
            )
            self.txt_block_detail.setPlainText(detail)

    def _audit_blockchain(self):
        audit = BlockchainService.audit_chain_integrity()
        if audit["valid"]:
            QMessageBox.information(
                self,
                "Audit Integritas Berhasil",
                f"✅ {audit['message']}\n\nSeluruh keterhubungan Previous Hash dan SHA-256 valid!"
            )
        else:
            QMessageBox.critical(
                self,
                "PELANGGARAN INTEGRITAS TERDETEKSI!",
                f"🚨 {audit['reason']}\n\nData pada Blok #{audit['tampered_index']} telah diubah atau dipalsukan!"
            )

    def _simulate_tamper(self):
        """Intentionally modify a block in database to demonstrate tamper detection to the professor."""
        row = self.block_table.currentRow()
        if row <= 0:
            QMessageBox.warning(self, "Peringatan", "Pilih blok non-genesis (Indeks > 0) untuk simulasi manipulasi.")
            return

        block_idx = int(self.block_table.item(row, 0).text().replace("#", ""))
        confirm = QMessageBox.question(
            self,
            "Konfirmasi Simulasi Tamper",
            f"Apakah Anda ingin mengubah data asset pada Blok #{block_idx} langsung di database MySQL?\n\n"
            f"Ini akan membuktikan bahwa algoritma Blockchain mendeteksi perubahan hash ilegal.",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            db.execute_query(
                "UPDATE blockchain SET asset_name = %s WHERE block_index = %s",
                ("TAMPERED_MALICIOUS_ASSET_NAME", block_idx)
            )
            QMessageBox.warning(
                self,
                "Data Berhasil Dimanipulasi di MySQL",
                f"Blok #{block_idx} telah diubah di database. Sekarang klik tombol '🔍 Audit Integritas Blockchain' untuk melihat deteksi pelanggaran integritas!"
            )
            self.refresh_blocks()

    def _repair_chain(self):
        """Recalculate hashes to restore valid chain state after tamper demonstration."""
        blocks = BlockchainService.get_all_blocks()
        for i, b in enumerate(blocks):
            prev_hash = "0"*64 if b["block_index"] == 0 else blocks[i-1]["block_hash"]
            recalc_hash = BlockchainService.calculate_block_hash(
                index=b["block_index"],
                timestamp=str(b["timestamp"]),
                asset_name=b["asset_name"],
                asset_type=b["asset_type"],
                asset_hash=b["asset_hash"],
                previous_hash=prev_hash,
                nonce=b["nonce"]
            )
            db.execute_query(
                "UPDATE blockchain SET previous_hash = %s, block_hash = %s WHERE id = %s",
                (prev_hash, recalc_hash, b["id"])
            )
            b["previous_hash"] = prev_hash
            b["block_hash"] = recalc_hash

        QMessageBox.information(self, "Pemulihan", "Seluruh hash rantai blockchain berhasil dikalkulasi ulang dan dipulihkan.")
        self.refresh_blocks()
