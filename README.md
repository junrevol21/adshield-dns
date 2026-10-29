# 🛡️ AdShield DNS - Windows DNS Sinkhole & Security Platform

Aplikasi DNS Sinkhole mandiri (*self-contained .exe package*) berkinerja tinggi untuk Windows dengan antarmuka desktop modern (vertical left sidebar, traffic light controls, standalone desktop app mode).

- **Standard Edition (Gratis Selamanya):** Perlindungan penuh untuk seluruh jaringan rumah atau kantor, filter blokir iklan, SafeSearch, dan manajemen per-perangkat.
- **Pro Edition:** Fitur otomatisasi tingkat lanjut seperti Auto-Lock Static IP, Anti-ISP Hijacking (DoH-Only), Live Latency Benchmark, dan Background 24/7 Engine.

---

## 🏆 Fitur: Standard Edition vs Pro Edition

| Kategori Fitur | Standard Edition | Pro Edition |
|---|---|---|
| **Kapasitas Aturan Iklan** | 🟢 **1.000.000+ Rules** (StevenBlack, Hagezi, OISD) | 🟢 **1.000.000+ Rules** + 🤖 **Auto-Update Tiap 24 Jam** |
| **Manajemen Klien (Per-Device)** | 🟢 **Bisa beda tiap HP** (Profil Anak, SafeSearch, Bypass) | 🟢 **Bisa beda tiap HP** + Deteksi Hardware Vendor MAC |
| **Blokir Layanan 1-Klik** | 🟢 **TikTok, Roblox, Game Online, Windows Spy, Judol** | 🟢 **12+ Kategori Lengkap** |
| **DNS Rewrite Lokal** | 🟢 **Pemetaan nama lokal (`router.lan -> 192.168.100.1`)** | 🟢 **Tersedia** |
| **RAM Caching & Query Log** | 🟢 **Sub-millisecond (< 1ms)** + Riwayat SQLite Real-Time | 🟢 **Tersedia** |
| **Custom Whitelist & Blacklist**| 🟢 **Dukungan tanpa batas** | 🟢 **Tersedia** |
| **Proteksi DNS Laptop 1-Klik** | 🟢 **Otomatis ganti adapter Wi-Fi ke 127.0.0.1** | 🟢 **Tersedia** |
| **Penguncian IP Adapter (Anti-Berubah)** | ⚪ Standar DHCP | ⭐ **1-Click Auto-Lock Static IP Adapter (`netsh`)** |
| **Mode Anti-ISP Hijacking** | ⚪ UDP Port 53 Standar | ⭐ **Mode Terenkripsi DoH Murni (Kebal Sensor ISP)** |
| **Uji Benchmark Latensi Upstream** | ⚪ Konfigurasi Manual | ⭐ **Live Benchmark 7 Server Dunia & Auto-Fastest** |
| **Manajemen Daya 24 Jam Laptop** | ⚪ Standar Windows | ⭐ **Smart Eco-Mode & Win32 Lid-Close 24/7 Run** |
| **Layanan Resmi Windows Service** | ⚪ Startup Shortcut | ⭐ **1-Click Install via Dashboard (`sc create`)** |
| **Teleporter Backup & Restore** | ⚪ Konfigurasi Lokal | ⭐ **1-Click Backup & Restore Konfigurasi JSON** |

---

## 🔑 Sistem Lisensi & Kupon Promo VIP

AdShield dilengkapi sistem verifikasi lisensi kriptografis berbasis Hardware GUID (Machine ID Windows) dan mendukung penukaran kupon promo VIP:
- **Kupon Eksklusif & Demo VIP Lifetime:**
  - `masjunganteng` (Kupon Eksklusif Mas Jun - Founder Lifetime PRO)
  - `PRO-VIP-2026`
  - `BETA-TESTER`
  - `SULTAN-BEAST`
  - `HEMAT100`
- Masukkan kupon di modal aktivasi (`Buka 7 Fitur Eksklusif PRO`) untuk langsung membuka seluruh fitur PRO.

---

## 🚀 Fitur Unggulan AdShield ULTRA

1. **Jendela Desktop Mandiri (Native macOS-Style Window):**
   - Berjalan dalam jendela native mandiri tanpa tab browser dan tanpa address bar.
   - Dilengkapi left vertical sidebar, navigasi seksi, dan traffic light controls (🔴 🟡 🟢).
   - Ikon perisai System Tray di pojok kanan bawah Windows taskbar.
2. **Penguncian IP Otomatis (Static IP Lock):**
   - Mendeteksi IP, subnet mask, dan gateway router.
   - Mengunci IP adapter Windows menjadi statis dalam 1 klik sehingga router reboot atau masa sewa DHCP habis tidak akan mengubah IP DNS.
3. **Pembaruan Otomatis 24 Jam (Smart Heuristic Auto-Update):**
   - Background thread otomatis memperbarui daftar filter setiap 24 jam tanpa mengganggu koneksi pengguna.
4. **Manajemen Klien Per-Device (Beda Aturan Tiap HP):**
   - 🧒 **Anak (Kids):** Otomatis SafeSearch, blokir game online (Roblox, FreeFire, Mobile Legends), TikTok, dan judi/pornografi.
   - 👨‍👩‍👧 **Standar:** Blokir iklan & pelacak umum.
   - 💼 **Kerja/Kantor:** Blokir media sosial dan games.
   - 🔓 **Bypass Penuh:** Tanpa blokir sama sekali (untuk keperluan developer).
5. **Mode Anti-Bypass & Anti-ISP Hijack (Encrypted DoH Only):**
   - Menghalau pembajakan DNS transparan dari ISP lokal (IndiHome, Telkom, FirstMedia) dengan merutekan query secara eksklusif melalui protokol HTTPS (DoH) terenkripsi.
6. **Alat Uji Latensi Upstream DNS (Benchmark Bawaan):**
   - Menguji latensi respon nyata secara *real-time* ke berbagai server dunia, menampilkan server tercepat, dan menerapkan dalam 1 klik.
7. **Pencatatan Riwayat Asinkron SQLite (Zero-Latency Logging):**
   - Query dicatat ke SQLite `data/adshield.db` via antrean batch tanpa memperlambat lalulintas DNS.

---

## 📦 Cara Menjalankan

1. Masuk ke folder: `dist\`
2. Klik ganda file: **`AdShield-DNS.exe`**
3. Aplikasi otomatis meminta hak Administrator (UAC) agar dapat mengikat port 53.
4. Jendela aplikasi mandiri bergaya desktop native akan langsung terbuka, dan ikon perisai aktif di System Tray pojok kanan bawah.

---

## 📁 Struktur Direktori Proyek

- `dist/AdShield-DNS.exe` : Executable mandiri (29.7 MB) siap pakai.
- `main.py` : Entrypoint utama aplikasi.
- `dns_engine.py` : Engine DNS UDP/TCP port 53, sinkhole matcher, RAM cache, dan DoH forwarder.
- `blocklist_manager.py` : Parser filter hosts, adblock syntax, dan pengelola service catalog.
- `database.py` : Database SQLite asinkron untuk pencatatan riwayat query.
- `windows_utils.py` : Utilitas sistem Windows (Anti-Sleep, Eco-Mode, ARP discovery, Windows Service, 1-Click Adapter DNS).
- `web_server.py` : Server REST API Bottle responsif port 5380.
- `tray_app.py` : GUI System Tray Windows.
- `static/index.html` : Antarmuka Web Dashboard responsif dark mode.
- `data/` : Konfigurasi `config.json`, database `adshield.db`, whitelist, blacklist, dan cache filter.
- `.backups/` : Kumpulan restore point setiap sesi modifikasi kode.
