# 🛡️ SecureVault – Secure Communication & Data Protection System

Aplikasi Desktop Terintegrasi untuk Perlindungan Data, Komunikasi Rahasia, dan Audit Integritas Aset Kriptografi.
**Tugas Akhir Mata Kuliah Kriptografi - Program Studi Informatika**

---

## 📌 1. Ringkasan Proyek

**SecureVault** adalah platform keamanan data desktop multi-lapisan (*defense-in-depth*) yang dirancang untuk melindungi kerahasiaan (*confidentiality*), integritas (*integrity*), dan autentikasi (*authenticity*) informasi pengguna. Aplikasi ini menggabungkan algoritma kriptografi klasik dan modern, steganografi citra digital, buku besar integritas berbasis *blockchain* sederhana, serta otentikasi perangkat keras (*hardware-backed security*) Windows Hello dan USB Security Dongle.

---

## 🚀 2. Fitur Utama & Kriteria Kriptografi

### A. Autentikasi Multi-Faktor (MFA) & Hardware Security
- **Argon2id Password Hashing (RFC 9106):** Perlindungan kata sandi anti-GPU/ASIC dengan memory-hard parameters (Memory: 64 MB, Iterasi: 3, Paralelisme: 4 threads, Salt unik 128-bit).
- **Windows Hello Biometrik:** Autentikasi biometrik bawaan Windows (Pengenalan Wajah / Sidik Jari / Windows PIN) melalui integrasi Windows Credential API & UserConsentVerifier.
- **USB Security Dongle:** Pengecekan perangkat penyimpanan fisik USB yang terdaftar melalui ekstraksi *Volume Serial Number* dan challenge-token bertanda tangan kriptografis SHA-256.
- **Mode Pengembangan (Dev Mode):** Menyediakan fallback transparan berlabel eksplisit saat perangkat biometrik/dongle fisik tidak terpasang di komputer penguji.

### B. Super-Enkripsi Pesan Teks (Multilayer Cryptography)
- **Pipeline:** Plaintext → **Vigenère Cipher (Klasik)** → **AES-256-GCM (Modern AEAD)** → Ciphertext.
- **Pipeline Dekripsi:** Ciphertext → **AES-256-GCM Decryption** → **Vigenère Decryption** → Plaintext.
- Menggunakan Nonce acak 96-bit unik CSPRNG pada setiap proses enkripsi AES-GCM (mencegah *nonce-reuse attack*).
- Menampilkan inspeksi transparan hasil setiap tahapan (Intermediate Stage 1 dan Stage 2), tag autentikasi 128-bit, serta pendeteksian modifikasi ciphertext (*tamper resistance*).
- Disertai anotasi edukatif mengenai keterbatasan Vigenère cipher terhadap analisis frekuensi / Kasiski.

### C. Enkripsi File Tingkat Lanjut (ChaCha20-Poly1305)
- Mengamankan seluruh format file (`.pdf`, `.docx`, `.txt`, `.jpg`, `.png`, `.zip`, dll.).
- Menggunakan **ChaCha20-Poly1305 AEAD** dengan arsitektur *chunked authenticated streaming* (ukuran blok 64 KB) sehingga mampu menangani file besar tanpa membebani memori RAM.
- Verifikasi *bit-for-bit fidelity* berbasis SHA-256 untuk memastikan file hasil dekripsi identik 100% dengan file asli.

### D. Enkripsi Database (Database-Level AES-256-GCM)
- Seluruh pesan antar pengguna disimpan dalam database MySQL dalam keadaan terenkripsi (*ciphertext*).
- Nonce, authentication tag, dan metadata algoritma disimpan pada kolom terpisah.
- **Pemisahan Pengelolaan Kunci:** Kunci enkripsi diderivasi secara dinamis di memori (*in-memory session keys*) dan tidak pernah disimpan dalam format teks polos (*plaintext*) di database.

### E. Steganografi Gambar (LSB + Authenticated Encryption)
- Menyisipkan pesan rahasia ke dalam piksel citra digital menggunakan metode *Least Significant Bit* (LSB).
- Pesan dienkripsi dengan AES-256-GCM sebelum disisipkan ke dalam piksel gambar.
- Dilengkapi dengan *dynamic capacity meter* yang menghitung batas ukuran bit gambar cover sebelum proses penyisipan dilakukan.
- Output disimpan dalam format PNG *lossless* untuk mencegah kompresi piksel.

### F. Blockchain Sederhana untuk Integritas Aset
- Mencatat jejak digital (*audit trail*) aset penting (file terenkripsi, gambar stego, transaksi data).
- Struktur blok: `Index`, `Timestamp`, `Asset Name`, `Asset Hash (SHA-256)`, `Previous Hash`, `Nonce`, dan `Block Hash`.
- Dilengkapi tombol **Audit Integritas Blockchain** untuk memvalidasi rantai hash dan mendeteksi manipulasi database.
- Dilengkapi tombol **Simulasi Manipulasi (Tamper Test)** untuk demonstrasi pengujian di hadapan dosen penguji.

---

## 📂 3. Struktur Direktori Proyek

```
SecureVault/
│
├── main.py                     # Entry point aplikasi (Inisialisasi PySide6 & Session)
├── requirements.txt            # Daftar pustaka dependensi Python
├── .env                        # Konfigurasi database & environment variables
├── .env.example                # Template konfigurasi environment
├── .gitignore                  # Berkas pengecualian Git
├── README.md                   # Dokumentasi lengkap sistem
│
├── config/
│   ├── settings.py             # Konstanta aplikasi, konfigurasi path, dan flag MFA
│   └── database.py             # Database pool connection & auto-migration MySQL
│
├── database/
│   ├── schema.sql              # Struktur tabel database MySQL
│   └── seed.sql                # Data awal / Genesis block
│
├── core/
│   ├── auth.py                 # Manajemen sesi aktif pengguna dan logout sanitization
│   ├── key_manager.py          # Derivasi kunci HKDF-SHA256 di memori RAM
│   └── security.py             # Argon2id hasher dan fungsi kriptografi utilitas
│
├── crypto/
│   ├── vigenere.py             # Implementasi Vigenère Cipher (Klasik)
│   ├── aes.py                  # Implementasi AES-256-GCM (Modern AEAD)
│   ├── chacha20.py             # Implementasi ChaCha20-Poly1305 streaming chunked
│   └── hashing.py              # SHA-256 hashing utilitas untuk file & blok
│
├── hardware/
│   ├── biometric.py            # Integrasi sensor Windows Hello biometrik
│   └── dongle.py               # Pendeteksian & challenge token USB Security Dongle
│
├── services/
│   ├── auth_service.py         # Logika registrasi, verifikasi password & MFA
│   ├── message_service.py      # Enkripsi & riwayat pesan database
│   ├── file_service.py         # Manajemen enkripsi file vault & hashing
│   ├── steganography_service.py# Enkripsi dan penyisipan LSB citra PNG
│   └── blockchain_service.py   # Pembuatan blok, penambangan hash, & audit integritas
│
├── ui/
│   ├── style.py                # Desain tema Dark Mode modern (QSS StyleSheet)
│   ├── login.py                # Antarmuka login dengan status hardware
│   ├── register.py             # Antarmuka registrasi akun Argon2id
│   ├── main_window.py          # Window utama dengan navigasi sidebar modern
│   ├── dashboard.py            # Tampilan statistik, profil, & log audit
│   ├── text_crypto.py          # Tampilan Super-Enkripsi teks 2 tahap
│   ├── file_manager.py         # Tampilan pengamanan file ChaCha20
│   ├── message.py              # Tampilan pesan terenkripsi antar pengguna
│   ├── steganography.py        # Tampilan encode & decode LSB steganografi
│   ├── blockchain.py           # Tampilan Blockchain Explorer & Tamper Test
│   ├── user_management.py      # Tampilan manajemen akun pengguna
│   └── settings.py             # Tampilan pairing USB Dongle & uji Windows Hello
│
├── storage/
│   ├── encrypted_files/        # Folder penyimpanan file terenkripsi (.svf)
│   ├── decrypted_files/        # Folder penyimpanan file hasil dekripsi
│   └── stego_images/           # Folder penyimpanan citra steganografi PNG
│
└── tests/
    ├── test_crypto.py          # Unit test Vigenère, AES-GCM, ChaCha20, Tamper
    ├── test_auth.py            # Unit test Argon2id & HKDF derivation
    ├── test_file.py            # Unit test ChaCha20 file roundtrip & bit fidelity
    ├── test_steganography.py   # Unit test LSB kapasitas & decode roundtrip
    └── test_blockchain.py      # Unit test pembentukan blok & verifikasi hash
```

---

## 🛠️ 4. Panduan Menjalankan Aplikasi

### Persyaratan Sistem:
1. **Python 3.11+** (Telah teruji pada Python 3.13)
2. **XAMPP / MySQL Server** (Aktifkan modul MySQL pada port 3306)
3. **Sistem Operasi:** Windows 10/11 (Dukungan Windows Hello & USB Token)

### Langkah Menjalankan:
1. Pastikan Apache/MySQL di XAMPP telah dinyalakan (*Start MySQL*).
2. Buka terminal (PowerShell atau Command Prompt) di folder proyek:
   ```powershell
   cd "D:\! KULIAHHHHHH COYYY\Coding Course\SMS 5\Project\SecureVault"
   ```
3. Pasang dependensi jika belum terpasang:
   ```powershell
   pip install -r requirements.txt
   ```
4. Jalankan aplikasi SecureVault:
   ```powershell
   python main.py
   ```

### Akun Uji Coba Default:
- **Username:** `admin` | **Password:** `admin123`
- **Username:** `dosen_penguji` | **Password:** `kripto2026`
- Anda juga dapat mendaftarkan akun baru secara bebas melalui tombol **"Daftar Akun Baru"**.

---

## 🧪 5. Menjalankan Pengujian Otomatis (Automated Unit Tests)

Untuk memvalidasi seluruh fungsi kriptografi, integritas data, dan algoritma:
```powershell
$env:PYTHONPATH="D:\! KULIAHHHHHH COYYY\Coding Course\SMS 5\Project\SecureVault"
python -m pytest tests/ -v
```
*Hasil: 12/12 unit tests berhasil diverifikasi 100% tanpa kegagalan.*

---

## 👥 6. Pembagian Tugas Kelompok (3 Anggota)

| Anggota | Fokus Tugas & Modul |
|---|---|
| **Anggota 1** | Autentikasi Pengguna, Registrasi, Password Hashing Argon2id, Windows Hello Biometric (`hardware/biometric.py`), USB Security Dongle (`hardware/dongle.py`), Integrasi Koneksi Database MySQL. |
| **Anggota 2** | Kriptografi Inti: Vigenère Cipher (`crypto/vigenere.py`), AES-256-GCM (`crypto/aes.py`), ChaCha20-Poly1305 Streaming File Vault (`crypto/chacha20.py`), Enkripsi Database Pesan. |
| **Anggota 3** | Steganografi Citra Digital LSB (`services/steganography_service.py`), Blockchain Asset Integrity Ledger (`services/blockchain_service.py`), Antarmuka Pengguna PySide6 Modern & Integrasi Dashboard. |

---

*SecureVault dikembangkan untuk memenuhi kriteria Tugas Akhir Kriptografi dengan standar keamanan, integritas, dan keterbacaan kode terbaik.*
