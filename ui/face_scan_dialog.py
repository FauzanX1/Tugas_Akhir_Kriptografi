"""
SecureVault - UI: Real-Time Face Recognition Scanner Dialog
Renders live camera feed, Haar Cascade face detection with HUD targeting overlays,
scanning animations, and cosine similarity matching.
"""

import cv2
import numpy as np
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QFrame, QMessageBox
)
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtCore import Qt, QTimer
from hardware.biometric import FaceRecognitionEngine

class FaceScanDialog(QDialog):
    MODE_VERIFY = "VERIFY"
    MODE_REGISTER = "REGISTER"

    def __init__(self, parent=None, mode="VERIFY", registered_template: np.ndarray = None):
        super().__init__(parent)
        self.mode = mode
        self.registered_template = registered_template
        self.captured_template = None
        self.verified_confidence = 0.0
        self.cancelled_by_user = False
        self.consecutive_matches = 0
        self.scan_line_y = 0
        self.scan_dir = 4

        self.setWindowTitle("SecureVault - Pemindai Biometrik Wajah (Face Scanner)")
        self.setFixedSize(560, 620)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.cap = None
        self._init_ui()
        self._start_camera()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header Title
        title_text = "🛡️ Verifikasi Wajah Biometrik" if self.mode == self.MODE_VERIFY else "📸 Registrasi Wajah Baru"
        title_lbl = QLabel(title_text)
        title_lbl.setStyleSheet("font-size: 18px; font-weight: bold; color: #38bdf8;")
        title_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_lbl)

        sub_text = (
            "Arahkan wajah Anda ke tengah kamera untuk otentikasi biometrik."
            if self.mode == self.MODE_VERIFY
            else "Posisikan wajah Anda di tengah kotak untuk mengambil sampel biometrik."
        )
        sub_lbl = QLabel(sub_text)
        sub_lbl.setStyleSheet("color: #94a3b8; font-size: 12px;")
        sub_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(sub_lbl)

        # Camera Viewfinder Card
        camera_frame = QFrame()
        camera_frame.setObjectName("Card")
        camera_frame.setStyleSheet("background-color: #000000; border: 2px solid #1e293b; border-radius: 12px;")
        cf_layout = QVBoxLayout(camera_frame)
        cf_layout.setContentsMargins(6, 6, 6, 6)

        self.lbl_video = QLabel("Memulai kamera...")
        self.lbl_video.setAlignment(Qt.AlignCenter)
        self.lbl_video.setFixedSize(508, 380)
        self.lbl_video.setStyleSheet("background-color: #0b1120; border-radius: 8px;")
        cf_layout.addWidget(self.lbl_video)

        layout.addWidget(camera_frame)

        # Status & Confidence Bar
        self.lbl_status = QLabel("Mencari wajah...")
        self.lbl_status.setAlignment(Qt.AlignCenter)
        self.lbl_status.setStyleSheet("font-size: 13px; font-weight: bold; color: #38bdf8;")
        layout.addWidget(self.lbl_status)

        self.progress_match = QProgressBar()
        self.progress_match.setRange(0, 100)
        self.progress_match.setValue(0)
        self.progress_match.setFixedHeight(12)
        layout.addWidget(self.progress_match)

        # Buttons
        btn_layout = QHBoxLayout()
        if self.mode == self.MODE_REGISTER:
            self.btn_action = QPushButton("📸 Ambil & Simpan Sampel Wajah")
            self.btn_action.setObjectName("PrimaryBtn")
            self.btn_action.setFixedHeight(40)
            self.btn_action.clicked.connect(self._capture_registration_sample)
            btn_layout.addWidget(self.btn_action)

        self.btn_cancel = QPushButton("Batal")
        self.btn_cancel.setObjectName("SecondaryBtn")
        self.btn_cancel.setFixedHeight(40)
        self.btn_cancel.clicked.connect(self._handle_cancel)
        btn_layout.addWidget(self.btn_cancel)

        layout.addLayout(btn_layout)

        # Timer for frame capture
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._process_frame)

    def _start_camera(self):
        try:
            self.cap = cv2.VideoCapture(0)
            if not self.cap.isOpened():
                QMessageBox.critical(self, "Error Kamera", "Tidak dapat membuka kamera webcam.")
                self.reject()
                return
            self.timer.start(33)  # ~30 FPS
        except Exception as e:
            QMessageBox.critical(self, "Error Kamera", f"Gagal mengakses webcam: {str(e)}")
            self.reject()

    def _process_frame(self):
        if not self.cap or not self.cap.isOpened():
            return

        ret, frame = self.cap.read()
        if not ret or frame is None:
            return

        # Flip horizontally for natural mirror feel
        frame = cv2.flip(frame, 1)
        h_frame, w_frame = frame.shape[:2]

        # Detect face
        detect_result = FaceRecognitionEngine.detect_face_roi(frame)

        if detect_result is not None:
            face_roi, (x, y, w, h) = detect_result

            # Draw HUD Futuristic Targeting Box
            corner_len = int(w * 0.2)
            color = (255, 180, 0)  # Cyan in BGR

            # Corner brackets
            cv2.line(frame, (x, y), (x + corner_len, y), color, 3)
            cv2.line(frame, (x, y), (x, y + corner_len), color, 3)
            cv2.line(frame, (x + w, y), (x + w - corner_len, y), color, 3)
            cv2.line(frame, (x + w, y), (x + w, y + corner_len), color, 3)
            cv2.line(frame, (x, y + h), (x + corner_len, y + h), color, 3)
            cv2.line(frame, (x, y + h), (x, y + h - corner_len), color, 3)
            cv2.line(frame, (x + w, y + h), (x + w - corner_len, y + h), color, 3)
            cv2.line(frame, (x + w, y + h), (x + w, y + h - corner_len), color, 3)

            # Laser scanner line animation inside face box
            self.scan_line_y += self.scan_dir
            if self.scan_line_y >= h or self.scan_line_y <= 0:
                self.scan_dir = -self.scan_dir
            
            line_y = y + int(self.scan_line_y)
            cv2.line(frame, (x + 5, line_y), (x + w - 5, line_y), (0, 255, 255), 2)

            # Extract features from current face ROI
            curr_feat = FaceRecognitionEngine.extract_features(face_roi)

            if self.mode == self.MODE_VERIFY:
                if self.registered_template is not None:
                    similarity = FaceRecognitionEngine.compare(curr_feat, self.registered_template)
                    pct = int(similarity * 100)
                    self.progress_match.setValue(pct)
                    self.verified_confidence = similarity * 100

                    if similarity >= FaceRecognitionEngine.MATCH_THRESHOLD:
                        self.consecutive_matches += 1
                        self.lbl_status.setText(f"✅ Wajah Cocok! ({similarity*100:.1f}%) Memverifikasi...")
                        self.lbl_status.setStyleSheet("font-size: 13px; font-weight: bold; color: #34d399;")
                        
                        # Match confirmed for 4 frames
                        if self.consecutive_matches >= 4:
                            self._stop_camera()
                            self.accept()
                            return
                    else:
                        self.consecutive_matches = max(0, self.consecutive_matches - 1)
                        self.lbl_status.setText(f"🔍 Memindai Wajah... (Kecocokan: {similarity*100:.1f}%)")
                        self.lbl_status.setStyleSheet("font-size: 13px; font-weight: bold; color: #38bdf8;")
                else:
                    # User hasn't registered a face template yet
                    self.lbl_status.setText("ℹ️ Template Wajah belum didaftarkan pada akun ini.")
                    self.lbl_status.setStyleSheet("font-size: 12px; color: #f59e0b;")

            elif self.mode == self.MODE_REGISTER:
                self.curr_detected_feat = curr_feat
                self.lbl_status.setText("👤 Wajah Terdeteksi dengan Jelas. Klik 'Ambil & Simpan Sampel Wajah'.")
                self.lbl_status.setStyleSheet("font-size: 13px; font-weight: bold; color: #34d399;")
                self.progress_match.setValue(100)

        else:
            self.lbl_status.setText("👤 Arahkan wajah menghadap kamera...")
            self.lbl_status.setStyleSheet("font-size: 13px; color: #94a3b8;")
            self.progress_match.setValue(0)
            self.consecutive_matches = 0

        # Convert frame to Qt QImage for display
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        h, w, ch = rgb_frame.shape
        bytes_per_line = ch * w
        q_img = QImage(rgb_frame.data, w, h, bytes_per_line, QImage.Format_RGB888)
        pix = QPixmap.fromImage(q_img).scaled(508, 380, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.lbl_video.setPixmap(pix)

    def _capture_registration_sample(self):
        if not hasattr(self, "curr_detected_feat") or self.curr_detected_feat is None:
            QMessageBox.warning(self, "Peringatan", "Wajah belum terdeteksi. Posisikan wajah Anda di depan kamera.")
            return

        self.captured_template = self.curr_detected_feat
        self._stop_camera()
        QMessageBox.information(
            self,
            "Sampel Wajah Berhasil Diambil",
            "Vektor biometrik wajah (1024-fitur kontras ternormalisasi) berhasil diekstraksi!\n"
            "Data wajah Anda telah terdaftar untuk otentikasi."
        )
        self.accept()

    def _handle_cancel(self):
        self.cancelled_by_user = True
        self._stop_camera()
        self.reject()

    def _stop_camera(self):
        if self.timer and self.timer.isActive():
            self.timer.stop()
        if self.cap:
            self.cap.release()
            self.cap = None

    def closeEvent(self, event):
        self._stop_camera()
        super().closeEvent(event)
