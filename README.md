# 🔍 BTC Rich Hunter — Maximum Performance Edition

> A high-speed Bitcoin cryptography exploration and education tool.  
> Supports Universal GPU · TPU · Multi-core CPU · Telegram Notifications · Key Range Selector

---

## 📋 Table of Contents

- [About](#about)
- [How It Works](#how-it-works)
- [Key Features](#key-features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [How to Use](#how-to-use)
- [Key Range Selection](#key-range-selection)
- [Telegram Notifications](#telegram-notifications)
- [Supported Accelerators](#supported-accelerators)
- [FAQ](#faq)
- [Donation](#donation)
- [Contact](#contact)

---

## About

**BTC Rich Hunter** is a cryptography research and education tool that randomly explores the Bitcoin private key space, then checks whether any derived Bitcoin address exists in a provided target address list (`btc.txt`).

> ⚠️ **Disclaimer**  
> This tool is created **purely for educational and cryptographic research purposes**.  
> The probability of finding an active private key by randomly scanning the full secp256k1 key space  
> (2²⁵⁶ possibilities) is practically **zero**. Please use it responsibly.

---

## How It Works

### 1. Core Concept

Every Bitcoin wallet has three core components:

```
Private Key (256-bit) ──► Public Key (secp256k1) ──► Bitcoin Address
```

This process is **one-way** — a private key can derive an address, but an address cannot be reversed back to a private key (the foundation of Bitcoin security).

### 2. Script Workflow

```
┌─────────────────────────────────────────────────────────┐
│                      START                              │
│                        │                                │
│          ┌─────────────▼────────────┐                   │
│          │  Load target address     │                   │
│          │  list from btc.txt       │                   │
│          │  → frozenset O(1) lookup │                   │
│          └─────────────┬────────────┘                   │
│                        │                                │
│          ┌─────────────▼────────────┐                   │
│          │  Select Key Range        │                   │
│          │  Full / Puzzle / Custom  │                   │
│          └─────────────┬────────────┘                   │
│                        │                                │
│     ┌──────────────────▼───────────────────┐            │
│     │         Parallel Workers             │            │
│     │  ┌─────────┐  ┌──────┐  ┌────────┐  │            │
│     │  │ CPU ×N  │  │ GPU  │  │  TPU   │  │            │
│     │  └────┬────┘  └──┬───┘  └───┬────┘  │            │
│     └───────┼──────────┼──────────┼───────┘            │
│             └──────────┴──────────┘                     │
│                        │                                │
│          ┌─────────────▼────────────┐                   │
│          │  Generate Private Key    │                   │
│          │  (random within range)   │                   │
│          └─────────────┬────────────┘                   │
│                        │                                │
│          ┌─────────────▼────────────┐                   │
│          │  Derive 5 address types  │                   │
│          │  P2PKH · P2WPKH · P2TR  │                   │
│          │  P2SH · P2PKH-Uncomp    │                   │
│          └─────────────┬────────────┘                   │
│                        │                                │
│          ┌─────────────▼────────────┐                   │
│          │  Match against targets   │                   │
│          │  (frozenset lookup)      │                   │
│          └─────────────┬────────────┘                   │
│                   Match?│                               │
│              No ◄───────┤────► Yes                      │
│           (repeat)      │      │                        │
│                         │  ┌───▼─────────────────┐      │
│                         │  │ Save → found.txt    │      │
│                         │  │ Send Telegram alert │      │
│                         │  └─────────────────────┘      │
└─────────────────────────────────────────────────────────┘
```

### 3. Bitcoin Address Derivation

From a single private key, the script derives **5 address types simultaneously**:

| Type | Format | Description |
|------|--------|-------------|
| **P2PKH** compressed | `1...` | Legacy standard (compressed pubkey) |
| **P2PKH** uncompressed | `1...` | Old legacy format (uncompressed pubkey) |
| **P2WPKH** | `bc1q...` | Native SegWit (Bech32) |
| **P2SH-P2WPKH** | `3...` | Wrapped SegWit |
| **P2TR** | `bc1p...` | Taproot (Bech32m, BIP341) |

### 4. Cryptographic Library Selection

The script automatically selects the fastest available library:

```
coincurve (C-binding libsecp256k1)  →  10–50× faster
        ↓ (if not available)
bip_utils (pure Python)             →  fallback
```

### 5. Cryptographically Secure Random Generation

```python
# Using secrets.token_bytes() — CSPRNG (Cryptographically Secure PRNG)
# No bias, completely unpredictable
kb = secrets.token_bytes(32)

# For specific ranges: secrets.randbelow() — also CSPRNG
offset = secrets.randbelow(span + 1)
ki = start + offset
```

### 6. Performance Estimates

| Mode | Estimated Speed |
|------|----------------|
| CPU (1 core, bip_utils) | ~500 – 1,000 keys/sec |
| CPU (1 core, coincurve) | ~5,000 – 15,000 keys/sec |
| CPU (8 cores, coincurve) | ~40,000 – 100,000 keys/sec |
| GPU NVIDIA (CuPy) | ~50,000 – 500,000 keys/sec* |
| GPU Apple MPS | ~20,000 – 150,000 keys/sec* |

\* Bottleneck remains on the CPU since secp256k1 has no native GPU kernel.

---

## Key Features

- 🚀 **Multi-accelerator** — NVIDIA (CuPy/PyTorch), AMD (ROCm), Intel (IPEX), Apple (MPS), Google TPU (JAX)
- ⚡ **Multi-core CPU** — Choose 1/2/4/8/16/all cores
- 🔀 **Hybrid Mode** — GPU + CPU running simultaneously
- 🎯 **5 Address Types** — P2PKH, P2WPKH, P2TR, P2SH, P2PKH-Uncomp
- 📂 **`.gz` File Support** — Read large address lists without extracting
- 🔑 **Key Range Selector** — Full / Puzzle Presets / Custom Hex Range
- 📱 **Telegram Notifications** — Auto-send message + `found.txt` attachment on match
- ✅ **Independent Verification** — Re-derives address upon any match found
- 💾 **Auto-save** — All results stored in `found.txt`
- 🖥 **Multi-machine** — Run on VPS and home PC simultaneously, all reporting to the same Telegram

---

## System Requirements

- **Python** 3.8 or newer
- **OS**: Windows / Linux / macOS
- **RAM**: Minimum 512 MB (more recommended if btc.txt is large)
- **Disk**: Depends on target file size

### Required Python Libraries

```bash
pip install coincurve bip_utils base58 colorama requests
```

### Optional Libraries (GPU Acceleration)

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

## Installation

### Step 1 — Clone or download the script

```bash
git clone https://github.com/syabiz/BTCRichHunter.git
cd BTCRichHunter
```

Or download `btc_hunter.py` directly from the repository.

### Step 2 — Install libraries

```bash
pip install coincurve bip_utils base58 colorama requests
```

### Step 3 — Prepare your target file

Create `btc.txt` and fill it with Bitcoin addresses (one per line):

```
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
```

Lines starting with `#` are treated as comments and ignored.

**Optional** — Use the public Bitcoin address database (large file):

```bash
# Download Bitcoin address database ~1 GB+ (optional)
wget http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz
```

> If the `.gz` file is placed in the same directory, the script reads it automatically via streaming — no extraction needed.

### Step 4 — Run the script

```bash
python btc_hunter.py
```

---

## Configuration

`config.json` is created automatically on the first run:

```json
{
    "telegram": {
        "enabled": false,
        "bot_token": "YOUR_BOT_TOKEN",
        "chat_id": "YOUR_CHAT_ID",
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

| Parameter | Description |
|-----------|-------------|
| `telegram.enabled` | Enable or disable Telegram notifications |
| `telegram.bot_token` | Bot token obtained from @BotFather |
| `telegram.chat_id` | Target chat ID for notifications |
| `telegram.send_file` | Attach `found.txt` to Telegram message on match |
| `targets` | List of target address files to load |
| `found_file` | Output filename for saving matches |
| `gpu_batch` | Number of keys generated per GPU batch |
| `cpu_batch` | Number of keys processed before updating the shared counter |

---

## How to Use

### Running the Script

```bash
python btc_hunter.py
```

You can also specify target files directly via command-line arguments:

```bash
python btc_hunter.py btc.txt
python btc_hunter.py btc.txt Bitcoin_addresses_LATEST.txt.gz
```

### Interactive Setup Flow

After launching, the script guides you through several setup steps:

---

**① Telegram Setup** (optional)

```
Enable Telegram notifications? (y/n): y
BOT TOKEN  : 123456789:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
CHAT ID    : -100123456789
Send found.txt? (y/n) [y]: y
✅ Saved to config.json
```

---

**② Accelerator Detection**

```
🔍 Detecting accelerator...
  ✅ NVIDIA RTX 3080  [NVIDIA/CuPy]
```

---

**③ Select CPU Cores** (CPU-only or hybrid mode)

```
Select number of CPU Cores:
  [1] 1 core
  [2] 2 cores
  [3] 4 cores
  [4] 8 cores  ← all cores
Choice (1-4): 4
✅ CPU 8 cores
```

---

**④ Select Key Range**

```
╔══════════════════════════════════════════════════════════════════════╗
║  SELECT PRIVATE KEY RANGE                                            ║
╚══════════════════════════════════════════════════════════════════════╝

  [ 1] #66  — 66-bit  [66-bit]
       0x20000000000000…  →  0x3ffffffffffffff…
  [ 2] #67  — 67-bit  [67-bit]
  [ 3] #68  — 68-bit  [68-bit]
  ...
  [10] Custom — Enter your own range  [manual input]
  [11] Full  — Entire secp256k1 range (full random)  [default]

Choice (1-11): 11
  ✅ Mode: Full random range (secp256k1)
```

---

**⑤ Real-time Status Bar**

```
[CPU×8|W:8] Range:FULL Checked:1,234,567 Speed:82,310/s Avg:78,921/s Time:15s
```

The status bar shows the active accelerator, number of workers, key range mode, total keys checked, current speed, average speed, and elapsed time.

---

### When a Match is Found

```
════════════════════════════════════════════════════════════════════════
                    🎉  MATCH FOUND!
════════════════════════════════════════════════════════════════════════

⏳ Independent verification...
   Status    : ✅ VERIFIED

────────────────────────────────────────────────────────────────────────
  PRIVATE KEY
────────────────────────────────────────────────────────────────────────
  HEX        : 0000...xxxx
  WIF        : 5Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  PubKey (C) : 02xxxxxx...
  PubKey (U) : 04xxxxxx...

────────────────────────────────────────────────────────────────────────
  ALL ADDRESSES FROM THIS PRIVATE KEY
────────────────────────────────────────────────────────────────────────
  Legacy          (P2PKH)   [1...]   : 1Axxxxxx...   ◄ TARGET MATCH
  Native SegWit   (P2WPKH)  [bc1q...]: bc1qxxxxxx...
  Taproot         (P2TR)    [bc1p...]: bc1pxxxxxx...
  Wrapped SegWit  (P2SH)   [3...]   : 3xxxxxx...
  Legacy Uncomp.  (P2PKH)   [1...]   : 1Bxxxxxx...
════════════════════════════════════════════════════════════════════════

💾 Saved → found.txt
📨 Sending Telegram notification...
  ✅ Message sent
  📎 Sending found.txt...
  ✅ File sent

Continue searching? (y/n):
```

Choosing `y` restarts all workers cleanly with the same configuration and range. Choosing `n` exits with final statistics.

### Stopping the Script

Press `Ctrl+C` at any time. Final statistics will be displayed:

```
📊 Final Statistics
   Accelerator : CPU — Intel Core i9
   Crypto lib  : coincurve
   Total Checked: 12,345,678
   Time         : 163.2s
   Average      : 75,645/s

Done.
```

---

## Key Range Selection

This feature lets you focus the search on a specific key range — useful for Bitcoin puzzle research or testing specific key segments.

### Bitcoin Puzzle Presets

| Option | Puzzle | Bit Width | Start |
|--------|--------|-----------|-------|
| `[1]` | #66 | 66-bit | `0x20000000000000000` |
| `[2]` | #67 | 67-bit | `0x40000000000000000` |
| `[3]` | #68 | 68-bit | `0x80000000000000000` |
| `[4]` | #69 | 69-bit | `0x100000000000000000` |
| `[5]` | #70 | 70-bit | `0x200000000000000000` |
| `[6]` | #71 | 71-bit | `0x400000000000000000` |
| `[7]` | #72 | 72-bit | `0x800000000000000000` |
| `[8]` | #75 | 75-bit | `0x40000000000000000000` |
| `[9]` | #160 | 160-bit | Full P2PKH space |

### Custom Range

Choose option `[10]` then enter your start and end values in hex:

```
Start (hex): 0x400000000000000000
End   (hex): 0x7fffffffffffffffff

  ✅ Range: 0x4000000000…  →  0x7fffffffff…  (~71-bit span)
```

Accepted input formats:
- `0x400000000000000000` — with `0x` prefix
- `400000000000000000` — without prefix
- `4000_0000_0000_0000_00` — underscores are silently ignored

Built-in validation rejects invalid inputs:
- ❌ `start >= end`
- ❌ `end >= secp256k1 curve order`
- ❌ `start <= 0`

### Full Range (Default)

Choose option `[11]` to search randomly across the entire secp256k1 key space (2²⁵⁶ possibilities).

> The selected range is applied consistently across **all** worker types — CPU, GPU (CuPy/PyTorch), and TPU (JAX). The status bar always shows the active range mode.

---

## Telegram Notifications

### Setting Up Your Bot

**Step 1** — Create a new bot via [@BotFather](https://t.me/BotFather):

```
/newbot
Bot name  : BTC Hunter Bot
Username  : mybtchunter_bot
→ You receive TOKEN: 123456789:AAHxxxxxxxx
```

**Step 2** — Get your Chat ID:
1. Send any message to your bot
2. Open: `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Look for `"chat":{"id": NUMBER}` — that number is your Chat ID

**Step 3** — Enter credentials when prompted, or edit `config.json` directly.

### Notification Preview

When a match is found, you receive a Telegram message like this:

```
🎉 BITCOIN FOUND!
🕐 2026-02-20 14:32:01
🖥 NVIDIA RTX 3080
✅ VERIFIED

🔑 PRIVATE KEY
HEX: 0000...xxxx
WIF: 5Hxxx...

🎯 TARGET [P2PKH]
1Axxxxxxxxxxxxx

📋 ALL ADDRESSES
P2PKH [1...]:    1Axxxx  ◄
P2WPKH [bc1q...]: bc1qxxxx
P2TR [bc1p...]:  bc1pxxxx
P2SH [3...]:     3xxxxx
P2PKH-U [1...]:  1Bxxxx
```

If `send_file` is enabled, `found.txt` is also sent as an attachment automatically.

### Multi-machine Setup

Run the script on multiple machines (VPS + home PC) using the same `config.json` (same `bot_token` and `chat_id`). All machines report to the same Telegram chat independently — no additional configuration required.

---

## Supported Accelerators

### Auto-detection Priority

```
TPU (JAX) → NVIDIA (CuPy) → NVIDIA (PyTorch) → AMD (ROCm) → Intel (IPEX) → Apple (MPS) → CPU
```

The script attempts auto-installation of CuPy (NVIDIA) and PyTorch ROCm (AMD) if the GPU is detected but the library is missing.

### Platform Details

| Hardware | Library | Notes |
|----------|---------|-------|
| NVIDIA GPU | CuPy (preferred) | Auto-installs if CUDA detected |
| NVIDIA GPU | PyTorch CUDA | Fallback if CuPy fails |
| AMD GPU | PyTorch ROCm | Auto-installs if ROCm detected |
| Intel GPU | PyTorch + IPEX | Requires manual installation |
| Apple Silicon | PyTorch MPS | macOS M1 / M2 / M3 / M4 |
| Google TPU | JAX | Google Colab / TPU VM |
| CPU | multiprocessing | All platforms, always available |

### Hybrid Mode

When a GPU is detected, you can optionally add extra CPU workers:

```
🚀 GPU_NVIDIA: NVIDIA RTX 3080
Add CPU workers for hybrid mode? (y/n): y

Select number of CPU Cores:
  [1] 1 core
  [2] 4 cores
  [3] 8 cores  ← all cores
Choice: 2

Active mode: GPU_NVIDIA+CPU×4
```

---

## FAQ

**Q: Can this tool really find an active wallet?**  
A: Mathematically, the probability is effectively absolute zero. The secp256k1 key space contains 2²⁵⁶ ≈ 10⁷⁷ possibilities. All computing power on Earth combined couldn't scan even a negligibly small fraction of it. This tool exists purely for cryptographic education.

**Q: Why should I install coincurve?**  
A: coincurve uses `libsecp256k1`, the official C library used by Bitcoin Core itself, making it 10–50× faster than pure Python implementations. It is strongly recommended.

**Q: Is it safe to run on a VPS?**  
A: Yes. The script sends no data anywhere except the Telegram notifications you configure yourself.

**Q: What should btc.txt contain?**  
A: One Bitcoin address per line. Supports P2PKH (`1...`), P2SH (`3...`), and bech32 (`bc1...`) formats. Lines starting with `#` are treated as comments and ignored.

**Q: What is the ideal size for btc.txt?**  
A: More addresses means a slightly higher chance of a match (still astronomically small). The public database `Bitcoin_addresses_LATEST.txt.gz` contains hundreds of millions of addresses (~1 GB compressed). The script supports streaming `.gz` files without extraction.

**Q: Why isn't GPU speed as high as expected?**  
A: The GPU generates random bytes in large batches, which is efficient. However, the core secp256k1 cryptographic computation (elliptic curve point multiplication) must still run on the CPU — no GPU kernel exists for it. The GPU accelerates the random generation step, not the primary derivation step.

**Q: Can I run this on Google Colab?**  
A: Yes, especially to leverage the TPU. Install the required dependencies at the start of your notebook and select the TPU/JAX option when prompted.

**Q: What happens if I choose to continue after a match?**  
A: All workers are terminated and restarted cleanly with the same configuration and key range. The counter resets and the search resumes automatically.

---

## Donation

If this tool has been useful for your education and learning, donations are greatly appreciated:

- **Bitcoin (BTC)** — `bc1qn6t8hy8memjfzp4y3sh6fvadjdtqj64vfvlx58`
- **Ethereum (ETH)** — `0x512936ca43829C8f71017aE47460820Fe703CAea`
- **Solana (SOL)** — `6ZZrRmeGWMZSmBnQFWXG2UJauqbEgZnwb4Ly9vLYr7mi`
- **PayPal** — [syabiz@yandex.com](mailto:syabiz@yandex.com)

Donations will be used for developing new features, server maintenance, and documentation.

---

## Contact

- **Web Script**: [https://github.com/syabiz/BTCRichHunter](https://github.com/syabiz/BTCRichHunter)
- **GitHub Issues**: [https://github.com/syabiz/BTCRichHunter/issues](https://github.com/syabiz/BTCRichHunter/issues)
- **Email**: [syabiz@yandex.com](mailto:syabiz@yandex.com)
- **Twitter**: [@syabiz](https://twitter.com/syabiz)

---

Thank you for using the BTC Rich Hunter! 🚀 Made with ❤️ for Bitcoin education and learning  
*Last updated: February 2026*
