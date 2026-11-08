"""
SecureVault - Hardware Security: Biometric Module (Windows Hello)
Interfaces with Windows Hello / Windows Biometric Credential APIs.
Identifies hardware availability, handles biometric verification requests,
and provides transparent development mode fallback with explicit hardware auditing.
"""

import os
import platform
import subprocess
import ctypes
from config.settings import DEV_MODE

class BiometricAuth:
    """
    Windows Hello Biometric Authentication Controller.
    """

    @classmethod
    def check_availability(cls) -> dict:
        """
        Check if Windows Hello biometric verification is supported and enrolled on the host.
        Returns a dict with availability status and technical explanation.
        """
        if platform.system() != "Windows":
            return {
                "available": False,
                "status": "UNSUPPORTED_OS",
                "message": "Autentikasi Windows Hello hanya tersedia pada sistem operasi Windows 10/11."
            }

        try:
            # Query Windows UserConsentVerifier via PowerShell
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
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=5
            )
            status_text = result.stdout.strip()
            
            if "Available" in status_text:
                return {
                    "available": True,
                    "status": "AVAILABLE",
                    "message": "Sensor Biometrik Windows Hello (Face / Fingerprint / PIN) aktif dan siap digunakan."
                }
            elif "DeviceNotPresent" in status_text:
                return {
                    "available": False,
                    "status": "DEVICE_NOT_PRESENT",
                    "message": "Hardware biometrik (IR Camera / Fingerprint sensor) tidak terdeteksi pada PC ini."
                }
            elif "NotConfiguredForUser" in status_text:
                return {
                    "available": False,
                    "status": "NOT_CONFIGURED",
                    "message": "Windows Hello belum dikonfigurasi untuk akun pengguna Windows saat ini."
                }
            else:
                return {
                    "available": False,
                    "status": "LIMITED_OR_UNAVAILABLE",
                    "message": f"Windows Hello tidak tersedia secara langsung (Status: {status_text or 'Unknown'})."
                }

        except Exception as e:
            return {
                "available": False,
                "status": "ERROR",
                "message": f"Pemeriksaan Windows Hello gagal: {str(e)}"
            }

    @classmethod
    def verify_biometric(cls, prompt_message: str = "Verifikasi identitas Anda untuk SecureVault") -> tuple[bool, str]:
        """
        Trigger native Windows Hello authentication verification prompt.
        If real hardware is not present and DEV_MODE is enabled, allow explicit Dev Mode bypass
        while explicitly logging that hardware authentication was bypassed.
        """
        status_info = cls.check_availability()

        if status_info["available"]:
            try:
                # Trigger native Windows Hello UI prompt via PowerShell
                ps_script = (
                    f"$ErrorActionPreference = 'Stop'; "
                    f"[Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null; "
                    f"Add-Type -AssemblyName System.Runtime.WindowsRuntime; "
                    f"$asTaskGeneric = [System.WindowsRuntimeSystemExtensions].GetMethods() | "
                    f"Where-Object {{ $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' }} | Select-Object -First 1; "
                    f"$task = $asTaskGeneric.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerificationResult]).Invoke($null, @([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('{prompt_message}'))); "
                    f"$task.Wait(); "
                    f"Write-Output $task.Result.ToString(); "
                )
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = result.stdout.strip()
                if "Verified" in output:
                    return True, "Verifikasi Windows Hello Berhasil."
                else:
                    return False, f"Verifikasi Biometrik ditolak pengguna atau gagal (Status: {output})."
            except Exception as e:
                return False, f"Terjadi kesalahan saat memanggil Windows Hello: {e}"

        # If real hardware is not available on this host:
        if DEV_MODE:
            return True, (
                "[DEV MODE] Hardware Windows Hello tidak terpasang pada komputer ini. "
                "Verifikasi dilanjutkan melalui Mode Pengembangan (Dev Mode Bypass)."
            )
        else:
            return False, f"Autentikasi Biometrik Gagal: {status_info['message']}"
