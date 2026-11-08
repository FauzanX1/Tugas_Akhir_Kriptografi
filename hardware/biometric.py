"""
SecureVault - Hardware Security: Biometric Module (Face Recognition & Windows Hello)
Implements live webcam facial detection (Haar Cascade), spatial normalized histogram feature extraction,
cosine distance matching, and fallback Windows Hello integration.
"""

import os
import json
import platform
import subprocess
import cv2
import numpy as np
from pathlib import Path
from typing import Optional, Tuple
from config.settings import DEV_MODE
from config.database import db

# Load pre-trained frontal face cascade classifier from OpenCV
CASCADE_PATH = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
face_cascade = cv2.CascadeClassifier(CASCADE_PATH)

class FaceRecognitionEngine:
    """
    Computer Vision engine for real-time face detection, feature extraction,
    and biometric facial verification.
    """

    FEATURE_SIZE = 1024
    MATCH_THRESHOLD = 0.78  # Cosine similarity threshold for verification

    @classmethod
    def detect_face_roi(cls, frame: np.ndarray) -> Optional[Tuple[np.ndarray, Tuple[int, int, int, int]]]:
        """
        Detect the most prominent face in a camera frame.
        Returns (cropped_face_bgr, (x, y, w, h)) or None.
        """
        if frame is None:
            return None

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.15,
            minNeighbors=5,
            minSize=(80, 80)
        )

        if len(faces) == 0:
            return None

        # Pick the largest detected face area (most prominent subject)
        largest_face = max(faces, key=lambda f: f[2] * f[3])
        x, y, w, h = largest_face
        face_roi = frame[y : y + h, x : x + w]
        return face_roi, (x, y, w, h)

    @classmethod
    def extract_features(cls, face_bgr: np.ndarray) -> np.ndarray:
        """
        Extract a normalized 1024-dimensional spatial-grid contrast-equalized feature vector
        from cropped face ROI. Resistant to ambient lighting variations via CLAHE.
        """
        if len(face_bgr.shape) == 3:
            gray = cv2.cvtColor(face_bgr, cv2.COLOR_BGR2GRAY)
        else:
            gray = face_bgr

        # Resize to fixed 128x128 resolution
        resized = cv2.resize(gray, (128, 128), interpolation=cv2.INTER_AREA)

        # Contrast Limited Adaptive Histogram Equalization
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        equalized = clahe.apply(resized)

        # Extract 8x8 spatial grid with 16-bin normalized histograms
        grid_hists = []
        cell_size = 16  # 128 / 8 = 16
        for r in range(0, 128, cell_size):
            for c in range(0, 128, cell_size):
                cell = equalized[r : r + cell_size, c : c + cell_size]
                hist = cv2.calcHist([cell], [0], None, [16], [0, 256])
                cv2.normalize(hist, hist)
                grid_hists.append(hist.flatten())

        feat = np.concatenate(grid_hists)
        norm = np.linalg.norm(feat)
        if norm > 1e-7:
            feat = feat / norm
        return feat

    @classmethod
    def compare(cls, feat1: np.ndarray, feat2: np.ndarray) -> float:
        """Calculate cosine similarity score between two face feature vectors (0.0 to 1.0)."""
        dot = np.dot(feat1, feat2)
        norm1 = np.linalg.norm(feat1)
        norm2 = np.linalg.norm(feat2)
        if norm1 < 1e-7 or norm2 < 1e-7:
            return 0.0
        similarity = dot / (norm1 * norm2)
        return float(np.clip(similarity, 0.0, 1.0))

    @classmethod
    def serialize_features(cls, feat: np.ndarray) -> str:
        """Serialize numpy vector to JSON string for database persistence."""
        return json.dumps(feat.tolist())

    @classmethod
    def deserialize_features(cls, json_str: str) -> Optional[np.ndarray]:
        """Deserialize JSON string from database into numpy vector."""
        if not json_str:
            return None
        try:
            arr = np.array(json.loads(json_str), dtype=np.float32)
            return arr
        except Exception:
            return None


class BiometricAuth:
    """
    Biometric Authentication Controller coordinating Face Recognition and Windows Hello.
    """

    @classmethod
    def check_availability(cls) -> dict:
        """
        Check biometric sensor availability (Webcam for Face Recognition & Windows Hello).
        """
        # Test webcam
        cap = cv2.VideoCapture(0)
        webcam_ok = cap.isOpened()
        if webcam_ok:
            cap.release()

        # Check Windows Hello
        hello_info = cls._check_windows_hello_availability()

        if webcam_ok:
            return {
                "available": True,
                "status": "AVAILABLE",
                "message": "Kamera Webcam aktif untuk Pemindaian Wajah (Face Recognition Biometrik)."
            }
        elif hello_info["available"]:
            return hello_info
        else:
            return {
                "available": False,
                "status": "DEVICE_NOT_PRESENT",
                "message": "Kamera webcam tidak terdeteksi pada sistem ini."
            }

    @classmethod
    def _check_windows_hello_availability(cls) -> dict:
        """Check native Windows Hello status."""
        if platform.system() != "Windows":
            return {"available": False, "status": "UNSUPPORTED_OS", "message": "Bukan sistem operasi Windows."}

        try:
            ps_script = (
                "$ErrorActionPreference = 'SilentlyContinue'; "
                "[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null; "
                "Add-Type -AssemblyName System.Runtime.WindowsRuntime; "
                "$asTaskGeneric = [System.WindowsRuntimeSystemExtensions].GetMethods() | "
                "Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1; "
                "if ($asTaskGeneric) { "
                "  $task = $asTaskGeneric.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerifierAvailability]).Invoke($null, @([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync())); "
                "  $task.Wait(); "
                "  Write-Output $task.Result.ToString(); "
                "} else { Write-Output 'Unavailable'; }"
            )
            result = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], capture_output=True, text=True, timeout=4)
            out = result.stdout.strip()
            if "Available" in out:
                return {"available": True, "status": "AVAILABLE", "message": "Windows Hello sensor aktif."}
        except Exception:
            pass

        return {"available": False, "status": "DEVICE_NOT_PRESENT", "message": "Sensor IR Windows Hello tidak terpasang."}

    @classmethod
    def get_user_face_template(cls, user_id: int) -> Optional[np.ndarray]:
        """Fetch enrolled biometric face vector from MySQL for given user."""
        row = db.fetch_one("SELECT face_template FROM users WHERE id = %s", (user_id,))
        if row and row.get("face_template"):
            return FaceRecognitionEngine.deserialize_features(row["face_template"])
        return None

    @classmethod
    def save_user_face_template(cls, user_id: int, template_vector: np.ndarray) -> bool:
        """Save enrolled biometric face vector to MySQL database."""
        serialized = FaceRecognitionEngine.serialize_features(template_vector)
        rows = db.execute_query(
            "UPDATE users SET face_template = %s, biometric_enabled = 1 WHERE id = %s",
            (serialized, user_id)
        )
        return rows > 0

    @classmethod
    def verify_biometric(cls, user_id: int = None, parent_window=None) -> tuple[bool, str]:
        """
        Launch live face recognition scanner dialog with camera feed.
        """
        # If user has a registered face or registering
        from ui.face_scan_dialog import FaceScanDialog
        
        registered_template = None
        if user_id:
            registered_template = cls.get_user_face_template(user_id)

        # Launch GUI camera scanner dialog
        dlg = FaceScanDialog(
            parent=parent_window,
            mode=FaceScanDialog.MODE_VERIFY,
            registered_template=registered_template
        )
        result = dlg.exec()
        if result == FaceScanDialog.Accepted:
            return True, f"Verifikasi Biometrik Wajah Berhasil (Kecocokan: {dlg.verified_confidence:.1f}%)."
        else:
            if dlg.cancelled_by_user:
                return False, "Pemindaian biometrik dibatalkan oleh pengguna."
            return False, "Verifikasi Wajah Gagal: Wajah tidak cocok dengan data biometrik yang terdaftar."
