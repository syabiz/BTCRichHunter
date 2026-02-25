# 🔍 BTC Rich Hunter — Maximum Performance Edition

> Alat eksplorasi dan edukasi kriptografi Bitcoin berkecepatan tinggi.  
> Mendukung GPU Universal · TPU · CPU Multi-core · Notifikasi Telegram · Range Key Selector

---

## 📋 Daftar Isi

- [Tentang](#tentang)
- [Cara Kerja](#cara-kerja)
- [Fitur Utama](#fitur-utama)
- [Persyaratan Sistem](#persyaratan-sistem)
- [Instalasi](#instalasi)
- [Konfigurasi](#konfigurasi)
- [Cara Menggunakan](#cara-menggunakan)
- [Pilihan Range Kunci](#pilihan-range-kunci)
- [Notifikasi Telegram](#notifikasi-telegram)
- [Akselerator yang Didukung](#akselerator-yang-didukung)
- [Pertanyaan Umum (FAQ)](#pertanyaan-umum-faq)
- [Donation](#donation)
- [Contact](#contact)

---

## Tentang

**BTC Rich Hunter** adalah alat riset dan edukasi kriptografi yang mengeksplorasi ruang private key Bitcoin secara acak, kemudian memeriksa apakah alamat Bitcoin yang dihasilkan terdapat dalam daftar alamat target (`btc.txt`).

> ⚠️ **Disclaimer**  
> Alat ini dibuat **semata-mata untuk tujuan edukasi dan penelitian kriptografi**.  
> Probabilitas menemukan private key yang aktif secara acak pada ruang penuh secp256k1  
> (2²⁵⁶ kemungkinan) secara praktis adalah **nol**. Gunakan secara bertanggung jawab.

---

## Cara Kerja

### 1. Konsep Dasar

Setiap dompet Bitcoin memiliki tiga komponen inti:

```
Private Key (256-bit) ──► Public Key (secp256k1) ──► Alamat Bitcoin
```

Proses ini **satu arah** — dari private key bisa diturunkan alamat, tetapi dari alamat tidak bisa dikembalikan ke private key (keamanan Bitcoin).

### 2. Alur Kerja Skrip

```
┌─────────────────────────────────────────────────────────┐
│                     MULAI                               │
│                        │                                │
│          ┌─────────────▼────────────┐                   │
│          │  Load daftar alamat      │                   │
│          │  target dari btc.txt     │                   │
│          │  → frozenset O(1) lookup │                   │
│          └─────────────┬────────────┘                   │
│                        │                                │
│          ┌─────────────▼────────────┐                   │
│          │  Pilih Range Kunci       │                   │
│          │  Full / Puzzle / Custom  │                   │
│          └─────────────┬────────────┘                   │
│                        │                                │
│     ┌──────────────────▼───────────────────┐            │
│     │         Worker Paralel               │            │
│     │  ┌─────────┐  ┌──────┐  ┌────────┐  │            │
│     │  │ CPU ×N  │  │ GPU  │  │  TPU   │  │            │
│     │  └────┬────┘  └──┬───┘  └───┬────┘  │            │
│     └───────┼──────────┼──────────┼───────┘            │
│             └──────────┴──────────┘                     │
│                        │                                │
│          ┌─────────────▼────────────┐                   │
│          │  Generate Private Key    │                   │
│          │  (acak dalam range)      │                   │
│          └─────────────┬────────────┘                   │
│                        │                                │
│          ┌─────────────▼────────────┐                   │
│          │  Turunkan 5 jenis alamat │                   │
│          │  P2PKH · P2WPKH · P2TR  │                   │
│          │  P2SH · P2PKH-Uncomp    │                   │
│          └─────────────┬────────────┘                   │
│                        │                                │
│          ┌─────────────▼────────────┐                   │
│          │  Cocokkan dengan target  │                   │
│          │  (frozenset lookup)      │                   │
│          └─────────────┬────────────┘                   │
│                   Cocok?│                               │
│              Tidak ◄────┤────► Ya                       │
│               (ulangi)  │     │                         │
│                         │  ┌──▼──────────────────┐      │
│                         │  │ Simpan → found.txt  │      │
│                         │  │ Kirim Telegram      │      │
│                         │  └─────────────────────┘      │
└─────────────────────────────────────────────────────────┘
```

### 3. Derivasi Alamat Bitcoin

Dari satu private key, skrip menurunkan **5 jenis alamat sekaligus**:

| Tipe | Format | Keterangan |
|------|--------|------------|
| **P2PKH** compressed | `1...` | Legacy standar (compressed pubkey) |
| **P2PKH** uncompressed | `1...` | Legacy lama (uncompressed pubkey) |
| **P2WPKH** | `bc1q...` | Native SegWit (Bech32) |
| **P2SH-P2WPKH** | `3...` | Wrapped SegWit |
| **P2TR** | `bc1p...` | Taproot (Bech32m, BIP341) |

### 4. Library Kriptografi

Skrip otomatis memilih library tercepat yang tersedia:

```
coincurve (C-binding libsecp256k1)  →  10–50× lebih cepat
        ↓ (jika tidak tersedia)
bip_utils (Python murni)            →  fallback
```

### 5. Mekanisme Random yang Aman

```python
# Menggunakan secrets.token_bytes() — CSPRNG (Cryptographically Secure)
# Tidak ada bias, tidak bisa diprediksi
kb = secrets.token_bytes(32)

# Untuk range tertentu: secrets.randbelow() — tetap CSPRNG
offset = secrets.randbelow(span + 1)
ki = start + offset
```

### 6. Performa

| Mode | Kecepatan Estimasi |
|------|--------------------|
| CPU (1 core, bip_utils) | ~500–1.000 kunci/detik |
| CPU (1 core, coincurve) | ~5.000–15.000 kunci/detik |
| CPU (8 core, coincurve) | ~40.000–100.000 kunci/detik |
| GPU NVIDIA (CuPy) | ~50.000–500.000 kunci/detik* |
| GPU Apple MPS | ~20.000–150.000 kunci/detik* |

*Bottleneck tetap di CPU karena secp256k1 tidak ada kernel GPU native.

---

## Fitur Utama

- 🚀 **Multi-akselerator** — NVIDIA (CuPy/PyTorch), AMD (ROCm), Intel (IPEX), Apple (MPS), Google TPU (JAX)
- ⚡ **CPU Multi-core** — Pilih 1/2/4/8/16/semua core
- 🔀 **Hybrid Mode** — GPU + CPU berjalan bersamaan
- 🎯 **5 Tipe Alamat** — P2PKH, P2WPKH, P2TR, P2SH, P2PKH-Uncomp
- 📂 **Support file .gz** — Baca daftar alamat besar tanpa ekstrak
- 🔑 **Key Range Selector** — Full / Puzzle Preset / Custom Hex Range
- 📱 **Notifikasi Telegram** — Pesan + lampiran `found.txt` otomatis
- ✅ **Verifikasi independen** — Re-derive alamat saat ada kecocokan
- 💾 **Auto-save** — Hasil tersimpan di `found.txt`
- 🖥 **Multi-mesin** — Jalankan di VPS + PC, semua lapor ke Telegram yang sama

---

## Persyaratan Sistem

- **Python** 3.8 atau lebih baru
- **OS**: Windows / Linux / macOS
- **RAM**: Minimum 512 MB (lebih banyak jika btc.txt besar)
- **Disk**: Sesuai ukuran file target

### Library Python (Wajib)

```bash
pip install coincurve bip_utils base58 colorama requests
```

### Library Opsional (GPU)

```bash
# NVIDIA CUDA 12
pip install cupy-cuda12x

# NVIDIA CUDA 11
pip install cupy-cuda11x

# AMD ROCm
pip install torch --index-url https://download.pytorch.org/whl/rocm6.0

# Intel GPU
pip install torch intel-extension-for-pytorch

# Apple MPS (macOS)
pip install torch

# Google TPU (Colab)
pip install "jax[tpu]" -f https://storage.googleapis.com/jax-releases/libtpu_releases.html
```

---

## Instalasi

### Langkah 1 — Clone atau download skrip

```bash
git clone https://github.com/syabiz/BTCRichHunter.git
cd BTCRichHunter
```

Atau download langsung `btc_hunter.py`.

### Langkah 2 — Install library

```bash
pip install coincurve bip_utils base58 colorama requests
```

### Langkah 3 — Siapkan file target

Buat file `btc.txt` dan isi dengan alamat Bitcoin target (satu per baris):

```
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
```

**Atau** gunakan database alamat publik Bitcoin (opsional, ukuran besar):

```bash
# Download database alamat ~1GB+ (opsional)
wget http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz
```

> Jika file `.gz` ada di direktori yang sama, skrip membacanya otomatis tanpa perlu diekstrak.

### Langkah 4 — Jalankan

```bash
python btc_hunter.py
```

---

## Konfigurasi

File `config.json` dibuat otomatis saat pertama kali dijalankan:

```json
{
    "telegram": {
        "enabled": false,
        "bot_token": "ISI_TOKEN_BOT",
        "chat_id": "ISI_CHAT_ID",
        "send_file": true
    },
    "targets": [
        "btc.txt",
        "Bitcoin_addresses_LATEST.txt.gz"
    ],
    "found_file": "found.txt",
    "gpu_batch": 8192,
    "cpu_batch": 1000
}
```

| Parameter | Keterangan |
|-----------|------------|
| `telegram.enabled` | Aktifkan notifikasi Telegram |
| `telegram.bot_token` | Token bot dari @BotFather |
| `telegram.chat_id` | ID chat tujuan notifikasi |
| `telegram.send_file` | Kirim `found.txt` sebagai lampiran |
| `targets` | Daftar file alamat target |
| `found_file` | Nama file penyimpan hasil |
| `gpu_batch` | Jumlah kunci per batch GPU |
| `cpu_batch` | Jumlah kunci per batch CPU sebelum update counter |

---

## Cara Menggunakan

### Menjalankan Skrip

```bash
python btc_hunter.py
```

Atau tentukan file target langsung via argumen:

```bash
python btc_hunter.py btc.txt
python btc_hunter.py btc.txt Bitcoin_addresses_LATEST.txt.gz
```

### Alur Interaktif

Setelah dijalankan, skrip memandu Anda melalui beberapa langkah:

**① Setup Telegram** (opsional)
```
Aktifkan notifikasi Telegram? (y/n): y
BOT TOKEN  : 123456789:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
CHAT ID    : -100123456789
Kirim found.txt? (y/n) [y]: y
```

**② Deteksi Akselerator**
```
🔍 Deteksi akselerator...
  ✅ NVIDIA RTX 3080  [NVIDIA/CuPy]
```

**③ Pilih Jumlah CPU Core** (jika CPU only atau hybrid)
```
Pilih jumlah CPU Core:
  [1] 1 core
  [2] 2 core
  [3] 4 core
  [4] 8 core  ← semua core
Pilihan (1-4): 4
```

**④ Pilih Range Kunci**
```
╔══════════════════════════════════════════════════════════════════════╗
║  PILIH RANGE PRIVATE KEY                                             ║
╚══════════════════════════════════════════════════════════════════════╝

  [ 1] #66  — 66-bit  [66-bit]
       0x20000000000000…  →  0x3ffffffffffffff…
  [ 2] #67  — 67-bit
  ...
  [10] Custom — Masukan range sendiri  [input manual]
  [11] Full  — Seluruh range secp256k1 (random acak)  [default]

Pilihan (1-11): 11
```

**⑤ Status Real-time**
```
[CPU×4|W:4] Range:FULL Dicek:1,234,567 Speed:42,310/s Avg:38,921/s Waktu:32s
```

### Saat Ada Kecocokan

Jika ditemukan kecocokan, layar akan menampilkan:

```
════════════════════════════════════════════════════════════════════════
                    🎉  KECOCOKAN DITEMUKAN!
════════════════════════════════════════════════════════════════════════

⏳ Verifikasi independen...
   Status    : ✅ VERIFIED

────────────────────────────────────────────────────────────────────────
  PRIVATE KEY
────────────────────────────────────────────────────────────────────────
  HEX        : 0000...xxxx
  WIF        : 5Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  PubKey (C) : 02xxxxxx...
  PubKey (U) : 04xxxxxx...

────────────────────────────────────────────────────────────────────────
  SEMUA ALAMAT DARI PRIVATE KEY INI
────────────────────────────────────────────────────────────────────────
  Legacy          (P2PKH)   [1...]   : 1Axxxxxx...   ◄ TARGET COCOK
  Native SegWit   (P2WPKH)  [bc1q...]: bc1qxxxxxx...
  Taproot         (P2TR)    [bc1p...]: bc1pxxxxxx...
  Wrapped SegWit  (P2SH)   [3...]   : 3xxxxxx...
  Legacy Uncomp.  (P2PKH)   [1...]   : 1Bxxxxxx...
════════════════════════════════════════════════════════════════════════

💾 Disimpan → found.txt
📨 Kirim Telegram ...
  ✅ Pesan terkirim
  📎 Kirim found.txt ...
  ✅ File terkirim

Lanjut mencari? (y/n):
```

### Menghentikan Skrip

Tekan `Ctrl+C` untuk menghentikan. Statistik akhir akan ditampilkan.

---

## Pilihan Range Kunci

Fitur ini memungkinkan pencarian difokuskan pada rentang tertentu, berguna untuk riset puzzle Bitcoin atau pengujian rentang spesifik.

### Preset Puzzle Bitcoin

| Pilihan | Puzzle | Range |
|---------|--------|-------|
| `[1]` | #66 | `0x20000000000000000` → `0x3ffffffffffffff` |
| `[2]` | #67 | `0x40000000000000000` → `0x7ffffffffffffff` |
| `[3]` | #68 | `0x80000000000000000` → `0xfffffffffffffff` |
| ... | ... | ... |
| `[9]` | #160 | Full P2PKH range |

### Custom Range

Pilih opsi `[10]` lalu masukan range dalam format hex:

```
Start (hex): 0x400000000000000000
End   (hex): 0x7fffffffffffffffff
```

Format yang diterima:
- `0x400000000000000000` — dengan prefix 0x
- `400000000000000000`  — tanpa prefix
- `4000_0000_0000_0000_00` — dengan underscore (diabaikan)

Validasi otomatis:
- ❌ Ditolak jika `start >= end`
- ❌ Ditolak jika `end >= secp256k1 order`
- ❌ Ditolak jika `start <= 0`

### Full Range (Default)

Pilih opsi `[11]` untuk pencarian acak di seluruh ruang kunci secp256k1 (2²⁵⁶ kemungkinan).

---

## Notifikasi Telegram

### Cara Setup Bot Telegram

**Langkah 1** — Buat bot baru via [@BotFather](https://t.me/BotFather):
```
/newbot
Nama bot: BTC Hunter Bot
Username: mybtchunter_bot
→ Dapat TOKEN: 123456789:AAHxxxxxxxx
```

**Langkah 2** — Dapatkan Chat ID:
1. Kirim pesan ke bot Anda
2. Buka URL: `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Cari `"chat":{"id": ANGKA}` — itulah Chat ID Anda

**Langkah 3** — Masukan saat skrip bertanya, atau edit `config.json`:
```json
"telegram": {
    "enabled": true,
    "bot_token": "123456789:AAHxxxxxxxxxxxxxxxx",
    "chat_id": "123456789",
    "send_file": true
}
```

### Multi-mesin (VPS + PC)

Jalankan skrip di beberapa mesin dengan `config.json` yang sama (token & chat_id sama). Semua mesin akan melaporkan ke Telegram yang sama secara otomatis.

---

## Akselerator yang Didukung

### Otomatis Terdeteksi

Skrip mendeteksi hardware secara otomatis dengan prioritas:

```
TPU (JAX) → NVIDIA (CuPy) → NVIDIA (PyTorch) → AMD (ROCm) → Intel (IPEX) → Apple (MPS) → CPU
```

### Detail per Platform

| Hardware | Library | Catatan |
|----------|---------|---------|
| NVIDIA GPU | CuPy (diutamakan) | Auto-install jika CUDA terdeteksi |
| NVIDIA GPU | PyTorch CUDA | Fallback jika CuPy gagal |
| AMD GPU | PyTorch ROCm | Auto-install jika ROCm terdeteksi |
| Intel GPU | PyTorch + IPEX | Perlu install manual |
| Apple Silicon | PyTorch MPS | macOS M1/M2/M3 |
| Google TPU | JAX | Google Colab / TPU VM |
| CPU | multiprocessing | Semua platform |

### Mode Hybrid

Saat GPU terdeteksi, Anda bisa menambah CPU worker:

```
🚀 GPU_NVIDIA: NVIDIA RTX 3080
Tambah CPU workers untuk hybrid mode? (y/n): y

Pilih jumlah CPU Core:
  [1] 1 core
  [2] 4 core
  [3] 8 core  ← semua core
Pilihan: 2

Mode aktif: GPU_NVIDIA+CPU×4
```

---

## Pertanyaan Umum (FAQ)

**Q: Apakah benar-benar bisa menemukan wallet aktif?**  
A: Secara matematis, probabilitasnya mendekati nol secara absolut. Ruang kunci secp256k1 memiliki 2²⁵⁶ ≈ 10⁷⁷ kemungkinan. Seluruh kekuatan komputasi di bumi pun tidak cukup untuk menyisir bahkan sebagian kecilnya. Alat ini murni untuk edukasi kriptografi.

**Q: Kenapa saya harus install coincurve?**  
A: coincurve menggunakan library C `libsecp256k1` (library resmi Bitcoin Core), sehingga 10–50× lebih cepat dari implementasi Python murni. Sangat direkomendasikan.

**Q: Apakah aman dijalankan di VPS?**  
A: Ya. Skrip tidak mengirim data ke mana pun kecuali notifikasi Telegram yang Anda konfigurasi sendiri.

**Q: File btc.txt harus berisi apa?**  
A: Satu alamat Bitcoin per baris. Bisa P2PKH (`1...`), P2SH (`3...`), atau bech32 (`bc1...`). Baris yang dimulai `#` dianggap komentar dan diabaikan.

**Q: Berapa ukuran ideal file btc.txt?**  
A: Lebih banyak alamat = lebih besar kemungkinan kecocokan (tetap sangat kecil). Database publik seperti `Bitcoin_addresses_LATEST.txt.gz` berisi ratusan juta alamat (~1GB compressed). Skrip mendukung streaming `.gz` tanpa ekstrak.

**Q: Kenapa speed GPU tidak sebesar yang diharapkan?**  
A: GPU digunakan untuk generate random bytes dalam batch besar. Namun komputasi kriptografi secp256k1 (EC point multiplication) tetap dilakukan di CPU karena tidak ada kernel GPU yang tersedia. GPU mempercepat bagian I/O random, bukan komputasi utama.

**Q: Apakah bisa dijalankan di Google Colab?**  
A: Ya, terutama untuk memanfaatkan TPU. Install dependensi terlebih dahulu dan gunakan opsi TPU/JAX.

---

## Donation

Jika alat ini bermanfaat untuk edukasi dan pembelajaran Anda, donasi sangat diapresiasi:

- **Bitcoin (BTC)** — `bc1qn6t8hy8memjfzp4y3sh6fvadjdtqj64vfvlx58`
- **Ethereum (ETH)** — `0x512936ca43829C8f71017aE47460820Fe703CAea`
- **Solana (SOL)** — `6ZZrRmeGWMZSmBnQFWXG2UJauqbEgZnwb4Ly9vLYr7mi`
- **PayPal** — [syabiz@yandex.com](mailto:syabiz@yandex.com)

Donasi akan digunakan untuk pengembangan fitur baru, pemeliharaan server, dan dokumentasi.

---

## Contact

- **Web Script**: [https://github.com/syabiz/BTCRichHunter](https://github.com/syabiz/BTCRichHunter)
- **GitHub Issues**: [https://github.com/syabiz/BTCRichHunter/issues](https://github.com/syabiz/BTCRichHunter/issues)
- **Email**: [syabiz@yandex.com](mailto:syabiz@yandex.com)
- **Twitter**: [@syabiz](https://twitter.com/syabiz)

---

Thank you for using the BTC Rich Hunter! 🚀 Made with ❤️ for Bitcoin education and learning  
*Last updated: February 2026*
