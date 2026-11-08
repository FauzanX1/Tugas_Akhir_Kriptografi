"""
SecureVault - UI: Secure Messaging (Database-Level AES-256-GCM Encryption)
Enables end-to-end encrypted messaging between registered users with transparent
database ciphertext, nonce, and authentication tag inspection.
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QTextEdit, QMessageBox,
    QFrame, QSplitter, QCheckBox
)
from PySide6.QtCore import Qt
from core.auth import session
from services.message_service import MessageService

class MessageView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_recipient_id = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        header = QVBoxLayout()
        title = QLabel("💬 Pesan Rahasia Terenkripsi Database (AES-256-GCM)")
        title.setObjectName("TitleLabel")
        desc = QLabel(
            "Mengirim dan menerima pesan antar pengguna. Pesan dienkripsi menggunakan AES-256-GCM "
            "sebelum disimpan di database MySQL. Nonce unik dan tag integritas disimpan terpisah."
        )
        desc.setObjectName("SubtitleLabel")
        desc.setWordWrap(True)
        header.addWidget(title)
        header.addWidget(desc)
        layout.addLayout(header)

        # Splitter: Contacts on left, Conversation on right
        splitter = QSplitter(Qt.Horizontal)

        # Left Card: Contact List
        contact_card = QFrame()
        contact_card.setObjectName("Card")
        cc_layout = QVBoxLayout(contact_card)
        cc_layout.setContentsMargins(14, 14, 14, 14)
        cc_layout.setSpacing(10)

        cc_title = QLabel("👥 Kontak Pengguna")
        cc_title.setObjectName("SectionHeader")
        cc_layout.addWidget(cc_title)

        self.contact_list = QListWidget()
        self.contact_list.setStyleSheet(
            "QListWidget::item { padding: 10px; border-bottom: 1px solid #1e293b; border-radius: 6px; } "
            "QListWidget::item:selected { background-color: #2563eb; color: white; }"
        )
        self.contact_list.itemClicked.connect(self._on_contact_selected)
        cc_layout.addWidget(self.contact_list)

        self.btn_refresh_contacts = QPushButton("🔄 Refresh Kontak")
        self.btn_refresh_contacts.setObjectName("SecondaryBtn")
        self.btn_refresh_contacts.clicked.connect(self.refresh_contacts)
        cc_layout.addWidget(self.btn_refresh_contacts)

        splitter.addWidget(contact_card)

        # Right Card: Conversation Area
        chat_card = QFrame()
        chat_card.setObjectName("Card")
        chat_layout = QVBoxLayout(chat_card)
        chat_layout.setContentsMargins(18, 16, 18, 16)
        chat_layout.setSpacing(12)

        # Chat Header
        chat_header = QHBoxLayout()
        self.lbl_chat_title = QLabel("Pilih kontak di sebelah kiri untuk memulai percakapan")
        self.lbl_chat_title.setObjectName("SectionHeader")
        chat_header.addWidget(self.lbl_chat_title)
        chat_header.addStretch()

        self.cb_show_raw = QCheckBox("Mode Inspeksi Ciphertext Mentah DB")
        self.cb_show_raw.setStyleSheet("color: #38bdf8; font-size: 11px;")
        self.cb_show_raw.toggled.connect(self._load_conversation)
        chat_header.addWidget(self.cb_show_raw)

        chat_layout.addLayout(chat_header)

        # Message History
        self.message_display = QTextEdit()
        self.message_display.setReadOnly(True)
        self.message_display.setStyleSheet("background-color: #0b1120; font-size: 13px; padding: 10px;")
        chat_layout.addWidget(self.message_display)

        # Input & Send Area
        input_layout = QHBoxLayout()
        self.msg_input = QTextEdit()
        self.msg_input.setPlaceholderText("Ketikkan pesan terenkripsi...")
        self.msg_input.setFixedHeight(70)

        self.btn_send = QPushButton("Kirim Pesan\n(AES-GCM)")
        self.btn_send.setObjectName("PrimaryBtn")
        self.btn_send.setFixedSize(110, 70)
        self.btn_send.clicked.connect(self._send_message)

        input_layout.addWidget(self.msg_input)
        input_layout.addWidget(self.btn_send)
        chat_layout.addLayout(input_layout)

        splitter.addWidget(chat_card)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)

        layout.addWidget(splitter, stretch=1)

    def refresh_contacts(self):
        user_id = session.get_user_id()
        if not user_id:
            return

        self.contact_list.clear()
        users = MessageService.get_all_users_except(user_id)

        for u in users:
            display_name = f"{u['username']}"
            if u.get("full_name"):
                display_name += f" ({u['full_name']})"
            
            item = QListWidgetItem(f"👤 {display_name}")
            item.setData(Qt.UserRole, u["id"])
            self.contact_list.addItem(item)

    def _on_contact_selected(self, item):
        self.selected_recipient_id = item.data(Qt.UserRole)
        self.lbl_chat_title.setText(f"Percakapan Terenkripsi dengan {item.text()}")
        self._load_conversation()

    def _load_conversation(self):
        if not self.selected_recipient_id:
            return

        user_id = session.get_user_id()
        messages = MessageService.get_messages_between(user_id, self.selected_recipient_id)

        html = []
        show_raw = self.cb_show_raw.isChecked()

        for m in messages:
            is_me = (m["sender_id"] == user_id)
            align = "right" if is_me else "left"
            bg_color = "#1e3a8a" if is_me else "#1e293b"
            sender_label = "Anda" if is_me else m["sender_name"]

            html.append(f"<div style='text-align: {align}; margin-bottom: 12px;'>")
            html.append(
                f"<div style='display: inline-block; background-color: {bg_color}; "
                f"padding: 10px 14px; border-radius: 10px; max-width: 75%; text-align: left;'>"
            )
            html.append(f"<div style='font-size: 11px; color: #93c5fd; font-weight: bold;'>{sender_label} • {m['created_at']}</div>")
            
            if show_raw:
                html.append("<div style='margin-top: 6px; font-family: monospace; font-size: 11px; color: #fde047;'>")
                html.append(f"<b>[MYSQL Ciphertext]:</b> {m['ciphertext'][:32]}...<br>")
                html.append(f"<b>[Nonce]:</b> {m['nonce']}<br>")
                html.append(f"<b>[Tag]:</b> {m['tag']}")
                html.append("</div>")
            else:
                html.append(f"<div style='margin-top: 4px; color: #ffffff;'>{m['plaintext']}</div>")

            html.append("</div></div>")

        self.message_display.setHtml("".join(html))
        # Scroll to bottom
        sb = self.message_display.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _send_message(self):
        if not self.selected_recipient_id:
            QMessageBox.warning(self, "Peringatan", "Pilih kontak penerima terlebih dahulu.")
            return

        text = self.msg_input.toPlainText().strip()
        if not text:
            return

        user_id = session.get_user_id()
        success, msg = MessageService.send_message(
            sender_id=user_id,
            recipient_id=self.selected_recipient_id,
            plaintext=text
        )

        if success:
            self.msg_input.clear()
            self._load_conversation()
        else:
            QMessageBox.critical(self, "Pengiriman Gagal", msg)
