# Install Dependencies

## Must
```bash
pip install coincurve bip_utils base58 colorama requests
```
> ⚡ `coincurve` = C-binding libsecp256k1 → 10-50× faster than pure Python

## NVIDIA GPU (select according to CUDA version)
```bash
pip install cupy-cuda12x #CUDA 12.x (RTX 30xx/40xx, A100, T4)
pip install cupy-cuda11x #CUDA 11.x (GTX 10xx/20xx)
```
Check the CUDA version: `nvcc --version` or `nvidia-smi`

## AMD GPUs
```bash
pip install torch --index-url https://download.pytorch.org/whl/rocm6.0
```

## Intel Arc/Xe GPUs
```bash
pip install torch intel-extension-for-pytorch
```

##Apple Silicon M1/M2/M3/M4
```bash
pip install torch # MPS is built-in on macOS 12.3+
```

## Google Colab TPU
```bash
pip install "jax[tpu]" -f https://storage.googleapis.com/jax-releases/libtpu_releases.html
```

---

# Target Files

## Option 1: btc.txt (custom)
Create a `btc.txt` file, filling in the Bitcoin addresses one by one line:
```
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297
```

## Option 2: Bitcoin_addresses_LATEST.txt.gz (50+ million addresses)
Download from: http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz
Place it in the same folder as the script.
**No need to extract** — the script directly reads the stream from the .gz file.

---

# Run

```bash
# Default (read from config.json)
python btc_hunter.py

# Specify manual file
python btc_hunter.py btc.txt
python btc_hunter.py Bitcoin_addresses_LATEST.txt.gz
python btc_hunter.py btc.txt Bitcoin_addresses_LATEST.txt.gz
```

---

# Multi-Machine (VPS + Home Computer)

Run the script on each machine separately.
All machines report to the same Telegram (same bot_token & chat_id in config.json).
Each machine generates keys independently — no coordination is required.

Estimated performance per machine:
| Hardware | Speed ​​(keys/s) |
|--------------------|--------------------|
| coincurve + 8 cores | ~30,000–80,000 |
| coincurve + 16 cores| ~60,000–150,000|
| NVIDIA RTX 3080 | ~200,000–500,000|
| NVIDIA A100 | ~500,000–1,000,000|
| bip_utils + 8 cores | ~4,000–16,000 |