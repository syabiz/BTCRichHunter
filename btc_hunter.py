#!/usr/bin/env python3
# ==============================================================================
#  Bitcoin Rich Hunter  —  MAXIMUM PERFORMANCE EDITION
#  ─────────────────────────────────────────────────────────────────────────────
#
# MAJOR OPTIMIZATIONS vs. previous versions:
# 1. coincurve (C-binding libsecp256k1) → 10-50x faster than bip_utils
# 2. Tight CPU loop (zero overhead per key, batch 1000 keys before lock)
# 3. GPU batch 8192 keys/call + async double-buffer
# 4. Target file: btc.txt OR Bitcoin_addresses_LATEST.txt.gz
# (gz is read streaming without extracting — saves RAM for 1GB+ files)
# 5. Frozenset for cache-friendly O(1) lookup
# 6. All CPU cores + GPU running simultaneously (hybrid mode)
#
# Universal GPU: NVIDIA (CuPy/PyTorch CUDA) | AMD (ROCm) |
# Intel (IPEX/XPU) | Apple (MPS)
# TPU: Google TPU v5e-1 (JAX)
# CPU: Multiprocessing, select 1/2/4/8/16/all cores
# Notification: Telegram Bot (message + found.txt file)
# Multi-machine: Run on VPS and home computer simultaneously,
# all report to the same Telegram
#
# Required installations:
# pip install coincurve bip_utils base58 colorama requests
# NVIDIA GPU: pip install cupy-cuda12x (CUDA 12)
# pip install cupy-cuda11x (CUDA 11)
# AMD GPU: pip install torch --index-url https://download.pytorch.org/whl/rocm6.0
# Intel GPU: pip install torch intel-extension-for-pytorch
# Apple GPU: pip install torch
# Colab TPU: pip install "jax[tpu]" -f https://storage.googleapis.com/jax-releases/libtpu_releases.html
# ==============================================================================

import os, sys, re, gzip, time, json, secrets, struct, hashlib
import ctypes, threading, subprocess, multiprocessing, io
from multiprocessing import Process, Value, Queue
from pathlib import Path

from colorama import Fore, Style, init as _ci
_ci(autoreset=True)

# ── Library kriptografi (coincurve >> bip_utils) ───────────────────────────────
try:
    from coincurve import PrivateKey as _CCKey
    CRYPTO = "coincurve"
except ImportError:
    _CCKey = None
    CRYPTO = "bip_utils"

try:
    from bip_utils import (
        WifEncoder, P2PKHAddrEncoder, P2WPKHAddrEncoder,
        P2TRAddrEncoder, P2SHAddrEncoder, Secp256k1PrivateKey,
    )
    BIP_UTILS_OK = True
except ImportError:
    BIP_UTILS_OK = False

try:
    import base58 as _b58mod
    BASE58_OK = True
except ImportError:
    BASE58_OK = False

if CRYPTO == "coincurve" and not BASE58_OK:
    CRYPTO = "bip_utils"   # coincurve butuh base58

SECP256K1_N = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
CONFIG_FILE = "config.json"
FOUND_FILE  = "found.txt"

# ==============================================================================
#  KRIPTOGRAFI CEPAT  (path coincurve — C library)
# ==============================================================================

def _sha256(d: bytes) -> bytes: return hashlib.sha256(d).digest()

def _ripe160(d: bytes) -> bytes:
    h = hashlib.new("ripemd160"); h.update(d); return h.digest()

def _hash160(d: bytes) -> bytes: return _ripe160(_sha256(d))

def _b58check(payload: bytes) -> str:
    cs = _sha256(_sha256(payload))[:4]
    return _b58mod.b58encode(payload + cs).decode()

# ── Bech32 / Bech32m encoder (pure Python, tidak butuh library luar) ──────────
_BC = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_poly(vals):
    G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    c = 1
    for v in vals:
        b = c >> 25; c = ((c & 0x1ffffff) << 5) ^ v
        for i in range(5): c ^= G[i] if (b >> i) & 1 else 0
    return c

def _hrp_exp(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _cvbits(data, fr, to, pad=True):
    acc = bits = 0; ret = []; maxv = (1 << to) - 1
    for v in data:
        acc = ((acc << fr) | v) & 0xffffffff; bits += fr
        while bits >= to: bits -= to; ret.append((acc >> bits) & maxv)
    if pad and bits: ret.append((acc << (to - bits)) & maxv)
    return ret

def _encode_bech32(hrp, wit_ver, wit_prog, bech32m=False):
    # wit_ver sudah 5-bit (0 atau 1), TIDAK perlu dikonversi.
    # Hanya wit_prog (bytes) yang dikonversi 8→5 bit.
    d = [wit_ver] + _cvbits(list(wit_prog), 8, 5)
    const = 0x2bc830a3 if bech32m else 1
    poly  = _bech32_poly(_hrp_exp(hrp) + d + [0]*6) ^ const
    ck    = [(poly >> 5*(5-i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BC[x] for x in d + ck)

def _p2wpkh(h160: bytes) -> str:          # bc1q...
    return _encode_bech32("bc", 0, h160)

def _p2tr(x_only: bytes) -> str:          # bc1p...
    return _encode_bech32("bc", 1, x_only, bech32m=True)

def _taptweak(pub_c: bytes) -> bytes:
    """BIP341 key-path tweak: Q = P + H_tapTweak(P)*G"""
    x = pub_c[1:]
    tag = b"TapTweak"
    th  = _sha256(tag)
    tweak = _sha256(th + th + x)
    if _CCKey:
        try:
            from coincurve import PublicKey as _CCPub
            Q = _CCPub(pub_c).add(tweak)
            return Q.format(compressed=True)[1:]   # x-only
        except Exception:
            pass
    return x   # fallback: x-only tanpa tweak (approximate)


def derive_addresses(privkey_bytes: bytes) -> dict:
    """
    Derive semua jenis alamat Bitcoin dari private key bytes.
    Menggunakan coincurve (C lib) jika tersedia, else bip_utils.
    """
    out = {}
    try:
        if _CCKey and BASE58_OK:
            # ═══ COINCURVE PATH (10-50× lebih cepat) ═══════════════════════
            pk    = _CCKey(privkey_bytes)
            pub_c = pk.public_key.format(compressed=True)    # 33 B
            pub_u = pk.public_key.format(compressed=False)   # 65 B

            h160_c = _hash160(pub_c)
            h160_u = _hash160(pub_u)

            # WIF
            out["wif"] = _b58check(b"\x80" + privkey_bytes + b"\x01")

            # P2PKH compressed  (1...)
            out["p2pkh"]        = _b58check(b"\x00" + h160_c)

            # P2PKH uncompressed  (1...)
            out["p2pkh_uncomp"] = _b58check(b"\x00" + h160_u)

            # P2WPKH native SegWit  (bc1q...)
            out["p2wpkh"]       = _p2wpkh(h160_c)

            # P2SH-P2WPKH wrapped SegWit  (3...)
            redeem = b"\x00\x14" + h160_c
            out["p2sh_p2wpkh"]  = _b58check(b"\x05" + _hash160(redeem))

            # P2TR Taproot  (bc1p...)
            try:    out["p2tr"] = _p2tr(_taptweak(pub_c))
            except: out["p2tr"] = None

        elif BIP_UTILS_OK:
            # ═══ BIP_UTILS PATH (fallback) ══════════════════════════════════
            priv  = Secp256k1PrivateKey.FromBytes(privkey_bytes)
            pub   = priv.PublicKey()
            pub_c = pub.RawCompressed().ToBytes()
            pub_u = pub.RawUncompressed().ToBytes()
            out["wif"]          = WifEncoder.Encode(priv.Raw().ToBytes(), True)
            out["p2pkh"]        = P2PKHAddrEncoder.EncodeKey(pub_c)
            out["p2wpkh"]       = P2WPKHAddrEncoder.EncodeKey(pub_c)
            out["p2sh_p2wpkh"]  = P2SHAddrEncoder.EncodeKey(pub_c)
            out["p2pkh_uncomp"] = P2PKHAddrEncoder.EncodeKey(pub_u)
            try:    out["p2tr"] = P2TRAddrEncoder.EncodeKey(pub_c)
            except: out["p2tr"] = None
        else:
            out["_err"] = "Tidak ada library kriptografi!"
    except Exception as e:
        out["_err"] = str(e)
    return out


def check_match(addresses: dict, targets: frozenset):
    for k, v in addresses.items():
        if v and v in targets:
            return k, v
    return None


def gen_key() -> bytes:
    """Generate valid secp256k1 private key (32 bytes) — full range."""
    while True:
        k = secrets.token_bytes(32)
        if 0 < int.from_bytes(k, "big") < SECP256K1_N:
            return k


def gen_key_in_range(start: int, end: int) -> bytes:
    """
    Generate private key secara kriptografis aman dalam range [start, end].
    Menggunakan secrets.randbelow() — tidak ada bias distribusi.
    """
    span = end - start
    if span <= 0:
        raise ValueError("Range tidak valid: start >= end")
    while True:
        offset = secrets.randbelow(span + 1)
        ki = start + offset
        if 0 < ki < SECP256K1_N:
            return ki.to_bytes(32, "big")


# ── Preset Range Puzzle Bitcoin (terkenal di komunitas) ───────────────────────
# Format: (label, start_hex, end_hex, bit_width)
PUZZLE_RANGES = [
    ("#66  — 66-bit",
     "0x0000000000000000020000000000000000",
     "0x000000000000000003ffffffffffffff00", 66),
    ("#67  — 67-bit",
     "0x0000000000000000040000000000000000",
     "0x000000000000000007ffffffffffffff00", 67),
    ("#68  — 68-bit",
     "0x0000000000000000080000000000000000",
     "0x00000000000000000fffffffffffffff00", 68),
    ("#69  — 69-bit",
     "0x0000000000000000100000000000000000",
     "0x00000000000000001fffffffffffffff00", 69),
    ("#70  — 70-bit",
     "0x0000000000000000200000000000000000",
     "0x00000000000000003fffffffffffffff00", 70),
    ("#71  — 71-bit",
     "0x0000000000000000400000000000000000",
     "0x00000000000000007fffffffffffffff00", 71),
    ("#72  — 72-bit",
     "0x0000000000000000800000000000000000",
     "0x00000000000000000fffffffffffffff000", 72),
    ("#75  — 75-bit",
     "0x00000000000000040000000000000000000",
     "0x0000000000000007fffffffffffffffffff", 75),
    ("#160 — 160-bit (full P2PKH)",
     "0x0000000000000000000000000000000000000001",
     hex(SECP256K1_N - 1), 160),
    ("Custom — Masukan range sendiri", None, None, 0),
    ("Full  — Seluruh range secp256k1 (random acak)",  None, None, -1),
]

def _parse_hex(s: str) -> int:
    s = s.strip().replace("0x","").replace("0X","").replace(" ","").replace("_","")
    return int(s, 16)

def _fmt_range(start: int, end: int) -> str:
    """Format range dalam hex pendek untuk tampilan."""
    sh = hex(start); eh = hex(end)
    if len(sh) > 22: sh = sh[:10] + "…" + sh[-8:]
    if len(eh) > 22: eh = eh[:10] + "…" + eh[-8:]
    span_bits = (end - start).bit_length()
    return f"{sh}  →  {eh}  (~{span_bits}-bit span)"

def select_key_range() -> tuple:
    """
    Tampilkan menu pilih range kunci.
    Kembalikan (start_int, end_int) atau (None, None) untuk full range.
    """
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║  PILIH RANGE PRIVATE KEY                                             ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")
    for i, (label, s, e, bits) in enumerate(PUZZLE_RANGES, 1):
        bit_str = ""
        if bits > 0:
            bit_str = f"  {Fore.YELLOW}[{bits}-bit]{Style.RESET_ALL}"
        elif bits == 0:
            bit_str = f"  {Fore.WHITE}[input manual]{Style.RESET_ALL}"
        else:
            bit_str = f"  {Fore.GREEN}[default]{Style.RESET_ALL}"
        s_short = ""
        if s and e:
            si = _parse_hex(s); ei = _parse_hex(e)
            hs = hex(si); he = hex(ei)
            hs = hs[:14]+"…" if len(hs)>14 else hs
            he = he[:14]+"…" if len(he)>14 else he
            s_short = f"\n       {Fore.WHITE}{hs}  →  {he}{Style.RESET_ALL}"
        print(f"  {Fore.CYAN}[{i:2}]{Style.RESET_ALL} {label}{bit_str}{s_short}")

    print()
    while True:
        try:
            raw = input(f"{Fore.WHITE}Pilihan (1-{len(PUZZLE_RANGES)}): {Style.RESET_ALL}").strip()
            idx = int(raw) - 1
            if not (0 <= idx < len(PUZZLE_RANGES)):
                raise ValueError()
        except (ValueError, KeyboardInterrupt):
            print(f"{Fore.RED}  Tidak valid, coba lagi.{Style.RESET_ALL}")
            continue

        label, s_hex, e_hex, bits = PUZZLE_RANGES[idx]

        # ── Full range ──────────────────────────────────────────────────────
        if bits == -1:
            print(f"\n  {Fore.GREEN}✅ Mode: Full random range (secp256k1){Style.RESET_ALL}")
            return (None, None)

        # ── Custom range ────────────────────────────────────────────────────
        if bits == 0:
            print(f"\n  {Fore.YELLOW}Masukan range dalam hex (contoh: 0x400000000000000000){Style.RESET_ALL}")
            while True:
                try:
                    start_raw = input(f"  {Fore.WHITE}Start (hex): {Style.RESET_ALL}").strip()
                    end_raw   = input(f"  {Fore.WHITE}End   (hex): {Style.RESET_ALL}").strip()
                    si = _parse_hex(start_raw)
                    ei = _parse_hex(end_raw)
                    if si <= 0:
                        print(f"  {Fore.RED}❌ Start harus > 0{Style.RESET_ALL}"); continue
                    if ei >= SECP256K1_N:
                        print(f"  {Fore.RED}❌ End melebihi secp256k1 order!{Style.RESET_ALL}"); continue
                    if si >= ei:
                        print(f"  {Fore.RED}❌ Start harus lebih kecil dari End!{Style.RESET_ALL}"); continue
                    span_bits = (ei - si).bit_length()
                    print(f"\n  {Fore.GREEN}✅ Range: {_fmt_range(si, ei)}{Style.RESET_ALL}")
                    return (si, ei)
                except Exception as ex:
                    print(f"  {Fore.RED}❌ Format salah: {ex}  — gunakan hex (0x...){Style.RESET_ALL}")

        # ── Preset range ────────────────────────────────────────────────────
        si = _parse_hex(s_hex)
        ei = _parse_hex(e_hex)
        if si <= 0 or ei >= SECP256K1_N or si >= ei:
            print(f"  {Fore.RED}❌ Range preset tidak valid!{Style.RESET_ALL}"); continue
        print(f"\n  {Fore.GREEN}✅ Preset {label}{Style.RESET_ALL}")
        print(f"     Range: {_fmt_range(si, ei)}")
        return (si, ei)


# ==============================================================================
#  LOAD TARGET — btc.txt  ATAU  .gz  (streaming, hemat RAM)
# ==============================================================================

def load_targets(path: str) -> frozenset:
    """
    Load alamat Bitcoin dari:
    - file .txt  (satu alamat per baris)
    - file .gz   (langsung streaming, tanpa extract)
    Kembalikan frozenset untuk lookup O(1).
    """
    p = Path(path)
    if not p.exists():
        # Buat template
        print(f"{Fore.RED}❌ File tidak ditemukan: {path}{Style.RESET_ALL}")
        if path.endswith(".gz"):
            print(f"{Fore.YELLOW}   Download dari: http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz{Style.RESET_ALL}")
        else:
            with open(path, "w") as f:
                f.write("# Satu alamat Bitcoin per baris\n"
                        "# 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n")
            print(f"{Fore.YELLOW}   Template dibuat: {path}{Style.RESET_ALL}")
        return frozenset()

    size_mb = p.stat().st_size / 1024 / 1024
    is_gz   = path.endswith(".gz")

    print(f"{Fore.CYAN}📂 Loading {path}  ({size_mb:.1f} MB){Style.RESET_ALL}")
    if is_gz:
        print(f"   {Fore.YELLOW}Mode: streaming gz (tidak perlu extract){Style.RESET_ALL}")
    print(f"   Harap tunggu ...", end="", flush=True)

    t0    = time.time()
    addrs = set()

    try:
        opener = gzip.open(path, "rt", encoding="ascii", errors="ignore") \
                 if is_gz else open(path, "r", encoding="ascii", errors="ignore")

        with opener as f:
            for line in f:
                ln = line.strip()
                # Filter: alamat Bitcoin valid dimulai 1/3/b (P2PKH/P2SH/bc1)
                if ln and not ln.startswith("#") and ln[0] in "13b":
                    addrs.add(ln)
                    # Progress setiap 5 juta
                    if len(addrs) % 5_000_000 == 0:
                        print(f"\r   {Fore.GREEN}{len(addrs)/1e6:.1f}M{Style.RESET_ALL} alamat dimuat ...", end="", flush=True)
    except Exception as e:
        print(f"\n{Fore.RED}❌ Error membaca file: {e}{Style.RESET_ALL}")
        return frozenset()

    elapsed = time.time() - t0
    result  = frozenset(addrs)
    print(f"\r   {Fore.GREEN}✅ {len(result):,} alamat unik dimuat dalam {elapsed:.1f}s{Style.RESET_ALL}")
    return result


# ==============================================================================
#  KONFIGURASI
# ==============================================================================

DEFAULT_CONFIG = {
    "telegram": {
        "enabled": False,
        "bot_token": "ISI_TOKEN_BOT",
        "chat_id":   "ISI_CHAT_ID",
        "send_file": True
    },
    "targets": [
        "btc.txt",
        "Bitcoin_addresses_LATEST.txt.gz"
    ],
    "found_file": "found.txt",
    "gpu_batch":  8192,
    "cpu_batch":  1000
}

def load_config() -> dict:
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        print(f"{Fore.YELLOW}⚙  config.json dibuat.{Style.RESET_ALL}")
        return dict(DEFAULT_CONFIG)
    with open(CONFIG_FILE) as f:
        cfg = json.load(f)
    for k, v in DEFAULT_CONFIG.items():
        if k not in cfg: cfg[k] = v
        elif isinstance(v, dict):
            for k2, v2 in v.items():
                if k2 not in cfg[k]: cfg[k][k2] = v2
    return cfg


# ==============================================================================
#  TELEGRAM
# ==============================================================================

def _tg(token, method, **kw):
    try:
        import requests
        r = requests.post(f"https://api.telegram.org/bot{token}/{method}",
                          timeout=30, **kw)
        return r.json()
    except Exception as e:
        print(f"\n{Fore.RED}Telegram {method}: {e}{Style.RESET_ALL}")
        return {}

def tg_msg(token, cid, text):
    _tg(token, "sendMessage", json={"chat_id":cid,"text":text,"parse_mode":"HTML"})

def tg_file(token, cid, path, caption=""):
    if not os.path.exists(path): return
    try:
        import requests
        with open(path, "rb") as fh:
            requests.post(f"https://api.telegram.org/bot{token}/sendDocument",
                          timeout=60,
                          data={"chat_id":cid,"caption":caption},
                          files={"document":fh})
    except Exception as e:
        print(f"\n{Fore.RED}Telegram file: {e}{Style.RESET_ALL}")

def tg_notify(cfg, result, verif, found_file):
    tg = cfg.get("telegram",{})
    if not tg.get("enabled"): return
    tok, cid = tg.get("bot_token",""), tg.get("chat_id","")
    if not tok or tok.startswith("ISI_"): return

    pk   = result["privkey_hex"]
    wif  = result.get("wif","N/A")
    addr = result["addr"]
    ts   = time.strftime("%Y-%m-%d %H:%M:%S")
    vs   = "✅ VERIFIED" if verif.get("ok") else "❓ UNVERIFIED"
    d    = verif.get("derived", {})
    rows = ""
    for k,lbl in [("p2pkh","P2PKH [1...]"),("p2wpkh","P2WPKH [bc1q...]"),
                  ("p2tr","P2TR [bc1p...]"),("p2sh_p2wpkh","P2SH [3...]"),
                  ("p2pkh_uncomp","P2PKH-U [1...]")]:
        v2 = d.get(k)
        if v2:
            mk = " ◄" if v2 == addr else ""
            rows += f"\n<code>{lbl}: {v2}{mk}</code>"

    msg = (f"🎉 <b>BITCOIN DITEMUKAN!</b>\n"
           f"🕐 {ts}\n🖥 {ACCEL_NAME}\n{vs}\n\n"
           f"🔑 <b>PRIVATE KEY</b>\n"
           f"HEX: <code>{pk}</code>\n"
           f"WIF: <code>{wif}</code>\n\n"
           f"🎯 <b>TARGET [{result['addr_type'].upper()}]</b>\n"
           f"<code>{addr}</code>\n\n"
           f"📋 <b>SEMUA ALAMAT</b>{rows}")

    print(f"\n{Fore.CYAN}📨 Kirim Telegram ...{Style.RESET_ALL}")
    r = _tg(tok, "sendMessage",
            json={"chat_id":cid,"text":msg,"parse_mode":"HTML"})
    if r.get("ok"):
        print(f"  {Fore.GREEN}✅ Pesan terkirim{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}❌ Gagal: {r}{Style.RESET_ALL}")

    if tg.get("send_file"):
        print(f"  {Fore.CYAN}📎 Kirim {found_file} ...{Style.RESET_ALL}")
        tg_file(tok, cid, found_file, caption=f"found.txt — {ts}")
        print(f"  {Fore.GREEN}✅ File terkirim{Style.RESET_ALL}")

def tg_test(cfg) -> bool:
    tg = cfg.get("telegram",{})
    if not tg.get("enabled"): return False
    tok, cid = tg.get("bot_token",""), tg.get("chat_id","")
    if not tok or tok.startswith("ISI_"): return False
    r = _tg(tok, "getMe")
    if r.get("ok"):
        name = r["result"].get("username","")
        print(f"  {Fore.GREEN}✅ Telegram: @{name}{Style.RESET_ALL}")
        tg_msg(tok, cid,
               f"🤖 <b>Bitcoin Hunter aktif</b>\n"
               f"⏰ {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
               f"🖥 {ACCEL_NAME} [{ACCEL_TYPE}]\n"
               f"🔍 Pencarian dimulai...")
        return True
    print(f"  {Fore.RED}❌ Telegram gagal: {r}{Style.RESET_ALL}")
    return False


# ==============================================================================
#  DETEKSI AKSELERATOR  (NVIDIA / AMD / Intel / Apple / TPU / CPU)
# ==============================================================================

ACCEL_TYPE    = "CPU"
ACCEL_NAME    = "CPU"
ACCEL_BACKEND = None

def _sh(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else ""
    except: return ""

def _cuda_ver():
    m = re.search(r"release (\d+)\.", _sh(["nvcc","--version"]))
    if m: return f"{m.group(1)}x"
    m2 = re.search(r"CUDA Version:\s*(\d+)\.", _sh(["nvidia-smi"]))
    if m2: return f"{m2.group(1)}x"
    return None

def _try_cupy():
    try:
        import cupy as cp
        cp.cuda.Device(0).use(); cp.array([1])
        cp.cuda.Stream.null.synchronize()
        try:
            p = cp.cuda.runtime.getDeviceProperties(0)
            n = p.get("name",b"NVIDIA GPU")
            return cp, (n.decode() if isinstance(n,bytes) else str(n))
        except: return cp, "NVIDIA GPU"
    except: return None, None

def _try_torch(device):
    try:
        import torch
        if device == "cuda":
            if not torch.cuda.is_available(): return None,None
            return torch, torch.cuda.get_device_name(0)
        if device == "mps":
            if not (sys.platform=="darwin" and torch.backends.mps.is_available()): return None,None
            chip = _sh(["sysctl","-n","machdep.cpu.brand_string"]) or "Apple Silicon"
            return torch, chip
        if device == "xpu":
            import intel_extension_for_pytorch as ipex  # noqa
            if not torch.xpu.is_available(): return None,None
            return torch, torch.xpu.get_device_name(0)
    except: pass
    return None, None

def _try_smi():
    out = _sh(["nvidia-smi","--query-gpu=name","--format=csv,noheader"])
    if out: return out.split("\n")[0]
    if os.path.exists("/proc/driver/nvidia/version"):
        try:
            with open("/proc/driver/nvidia/version") as f:
                return "NVIDIA GPU (" + f.read().split("\n")[0][:30] + ")"
        except: pass
    return None

def _try_rocm():
    rocm = (os.path.exists("/opt/rocm") or bool(_sh(["rocminfo"])) or bool(_sh(["rocm-smi"])))
    if not rocm: return None, None
    t, n = _try_torch("cuda")
    if t and any(x in (n or "").upper() for x in ["RADEON","RX","VEGA","NAVI","RDNA","GFX"]):
        return t, n
    # Nama dari rocm-smi
    out = _sh(["rocm-smi","--showproductname"])
    m = re.search(r"GPU\[.+\]\s*:\s*(.+)", out)
    return None, (m.group(1).strip() if m else "AMD GPU")

def _install_cupy(ver):
    pkg = f"cupy-cuda{ver}"
    print(f"  {Fore.YELLOW}⚙  Auto-install {pkg}...{Style.RESET_ALL}", flush=True)
    subprocess.run([sys.executable,"-m","pip","install",pkg,"-q"], capture_output=True)
    return _try_cupy()

def _install_rocm():
    print(f"  {Fore.YELLOW}⚙  Auto-install PyTorch ROCm...{Style.RESET_ALL}", flush=True)
    subprocess.run([sys.executable,"-m","pip","install","torch",
                    "--index-url","https://download.pytorch.org/whl/rocm6.0","-q"],
                   capture_output=True)
    return _try_torch("cuda")

def _try_jax_tpu():
    colab = bool(os.environ.get("COLAB_BACKEND_VERSION") or os.environ.get("TPU_NAME")
                 or os.path.exists("/dev/accel0"))
    try:
        import jax
        devs = jax.devices("tpu")
        if devs:
            n = str(devs[0]).split("(")[0].strip()
            return jax, f"TPU {n} ×{len(devs)}"
    except: pass
    if colab:
        print(f"  {Fore.YELLOW}⚙  Install jax[tpu]...{Style.RESET_ALL}", flush=True)
        subprocess.run([sys.executable,"-m","pip","install","jax[tpu]","-q",
                        "-f","https://storage.googleapis.com/jax-releases/libtpu_releases.html"],
                       capture_output=True)
        try:
            import importlib, jax; importlib.reload(jax)
            devs = jax.devices("tpu")
            if devs:
                n = str(devs[0]).split("(")[0].strip()
                return jax, f"TPU {n} ×{len(devs)}"
        except: pass
    return None, None

def detect_accel():
    global ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND
    print(f"\n{Fore.CYAN}🔍 Deteksi akselerator...{Style.RESET_ALL}")

    # 1. TPU
    j, n = _try_jax_tpu()
    if j:
        ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "TPU_JAX", n, j
        print(f"  {Fore.GREEN}✅ {n}  [TPU/JAX]{Style.RESET_ALL}"); return

    # 2. NVIDIA CuPy
    cp, n = _try_cupy()
    if cp:
        ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_NVIDIA", n, ("cupy","cuda")
        print(f"  {Fore.GREEN}✅ {n}  [NVIDIA/CuPy]{Style.RESET_ALL}"); return

    # 3. NVIDIA smi → install CuPy
    smi = _try_smi()
    if smi:
        print(f"  {Fore.YELLOW}⚠  GPU: {smi} — coba install CuPy{Style.RESET_ALL}")
        cv = _cuda_ver()
        if cv:
            cp2, n2 = _install_cupy(cv)
            if cp2:
                ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_NVIDIA", n2, ("cupy","cuda")
                print(f"  {Fore.GREEN}✅ {n2}  [NVIDIA/CuPy auto-install]{Style.RESET_ALL}"); return
        # fallback torch cuda
        t, n = _try_torch("cuda")
        if t:
            ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_NVIDIA", n, ("torch","cuda")
            print(f"  {Fore.GREEN}✅ {n}  [NVIDIA/PyTorch]{Style.RESET_ALL}"); return
        print(f"  {Fore.RED}❌ Driver/library GPU gagal{Style.RESET_ALL}")

    # 4. AMD ROCm
    t, n = _try_rocm()
    if t:
        ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_AMD", n, ("torch","cuda")
        print(f"  {Fore.GREEN}✅ {n}  [AMD/ROCm]{Style.RESET_ALL}"); return
    elif n:
        print(f"  {Fore.YELLOW}⚠  AMD GPU: {n} — install ROCm{Style.RESET_ALL}")
        t2, n2 = _install_rocm()
        if t2:
            ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_AMD", n2, ("torch","cuda")
            print(f"  {Fore.GREEN}✅ {n2}  [AMD/ROCm auto-install]{Style.RESET_ALL}"); return

    # 5. Intel
    t, n = _try_torch("xpu")
    if t:
        ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_INTEL", n, ("torch","xpu")
        print(f"  {Fore.GREEN}✅ {n}  [Intel/IPEX]{Style.RESET_ALL}"); return

    # 6. Apple MPS
    t, n = _try_torch("mps")
    if t:
        ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_APPLE", n, ("torch","mps")
        print(f"  {Fore.GREEN}✅ {n}  [Apple/MPS]{Style.RESET_ALL}"); return

    # 7. CPU
    print(f"  {Fore.WHITE}ℹ  Tidak ada GPU/TPU → CPU mode{Style.RESET_ALL}")


# ==============================================================================
#  WORKERS
# ==============================================================================

# ── CPU Worker  (tight loop, zero overhead) ────────────────────────────────────
def _cpu_worker(wid, counter, q, targets, stop_ev, batch_sz, key_range=(None,None)):
    """
    Loop paling ketat yang bisa dibuat di Python.
    - Batch 1000 keys sebelum lock counter (kurangi contention)
    - targets adalah frozenset (di-pass via shared memory Pickle)
    - key_range: (start_int, end_int) atau (None, None) untuk full range
    """
    local = 0
    N     = SECP256K1_N
    rng_start, rng_end = key_range
    use_range = (rng_start is not None and rng_end is not None)

    while not stop_ev.is_set():
        if use_range:
            kb = gen_key_in_range(rng_start, rng_end)
        else:
            kb = secrets.token_bytes(32)
            if not (0 < int.from_bytes(kb,"big") < N): continue
        addrs = derive_addresses(kb)
        m     = check_match(addrs, targets)
        if m:
            q.put({"privkey_hex": kb.hex(), "addr_type": m[0], "addr": m[1],
                   "wif": addrs.get("wif",""), "all_addresses": addrs})
            # Flush counter lalu tunggu stop signal
            with counter.get_lock(): counter.value += local + 1
            local = 0
            while not stop_ev.is_set(): time.sleep(0.05)
            return
        local += 1
        if local >= batch_sz:
            with counter.get_lock(): counter.value += local
            local = 0


# ── GPU Worker  (NVIDIA CuPy atau PyTorch CUDA/ROCm/MPS/XPU) ─────────────────
def _gpu_worker(counter, q, targets, stop_ev, backend, device, batch_sz=8192, key_range=(None,None)):
    """
    Generate random bytes di GPU (batch besar),
    derive alamat di CPU (secp256k1 tidak ada kernel GPU native).
    Double-buffer: generate batch N+1 di thread GPU sambil proses batch N di CPU.
    key_range: (start_int, end_int) atau (None, None) untuk full range.
    """
    N = SECP256K1_N
    rng_start, rng_end = key_range
    use_range = (rng_start is not None and rng_end is not None)
    rng_span  = (rng_end - rng_start) if use_range else None

    # ── Setup generator sesuai backend ──────────────────────────────────────
    if backend == "cupy":
        try:
            import cupy as cp
            cp.cuda.Device(0).use(); cp.array([1])
            def _gen(n):
                return cp.asnumpy(cp.random.bytes(n * 32))
        except Exception as e:
            print(f"\n{Fore.RED}CuPy init: {e} → CPU{Style.RESET_ALL}")
            _cpu_worker(0,counter,q,targets,stop_ev,1000,key_range); return
    else:
        try:
            import torch
            if device == "xpu":
                import intel_extension_for_pytorch  # noqa
            dev_obj = torch.device(device)
            torch.randint(0,256,(32,),dtype=torch.uint8,device=dev_obj).cpu()
            def _gen(n):
                t = torch.randint(0,256,(n*32,),dtype=torch.uint8,device=dev_obj)
                return t.cpu().numpy().tobytes()
        except Exception as e:
            print(f"\n{Fore.RED}Torch/{device} init: {e} → CPU{Style.RESET_ALL}")
            _cpu_worker(0,counter,q,targets,stop_ev,1000,key_range); return

    print(f"  {Fore.GREEN}✅ GPU worker aktif [{backend}/{device}] batch={batch_sz}{Style.RESET_ALL}")

    # Double-buffer: async generate di thread terpisah
    buf     = [None, None]
    buf_idx = [0]
    buf_lock= threading.Lock()
    gen_err = [False]

    def _prefetch(idx):
        try:
            buf[idx] = _gen(batch_sz)
        except Exception as e:
            print(f"\n{Fore.RED}GPU prefetch error: {e}{Style.RESET_ALL}")
            gen_err[0] = True

    # Isi buffer pertama
    _prefetch(0); _prefetch(1)

    cur = 0
    while not stop_ev.is_set():
        if gen_err[0]:
            _cpu_worker(0,counter,q,targets,stop_ev,1000,key_range); return

        raw = buf[cur]
        if raw is None: time.sleep(0.01); continue

        # Prefetch buffer berikutnya di background
        nxt = 1 - cur
        t = threading.Thread(target=_prefetch, args=(nxt,), daemon=True)
        t.start()

        cnt = 0
        for i in range(batch_sz):
            if stop_ev.is_set(): break
            chunk = bytes(raw[i*32:(i+1)*32]) if not isinstance(raw,(bytes,bytearray)) \
                    else raw[i*32:(i+1)*32]
            if len(chunk) < 32: continue
            ki = int.from_bytes(chunk,"big")
            # ── Mapping ke range jika aktif ──────────────────────────────────
            if use_range:
                ki = rng_start + (ki % (rng_span + 1))
                chunk = ki.to_bytes(32, "big")
            else:
                if not (0 < ki < N): continue
            addrs = derive_addresses(chunk)
            m     = check_match(addrs, targets)
            if m:
                q.put({"privkey_hex": chunk.hex(), "addr_type": m[0], "addr": m[1],
                       "wif": addrs.get("wif",""), "all_addresses": addrs})
                with counter.get_lock(): counter.value += cnt + 1
                while not stop_ev.is_set(): time.sleep(0.05)
                return
            cnt += 1

        with counter.get_lock(): counter.value += cnt
        t.join()
        cur = nxt


# ── TPU Worker  (JAX) ─────────────────────────────────────────────────────────
def _tpu_worker(counter, q, targets, stop_ev, batch_sz=4096, key_range=(None,None)):
    try:
        import jax, jax.numpy as jnp, jax.random as jr
        devs = jax.devices("tpu")
        if not devs: raise RuntimeError("Tidak ada TPU")
        print(f"  {Fore.GREEN}✅ TPU worker: {len(devs)} core, batch={batch_sz}{Style.RESET_ALL}")

        rng_start, rng_end = key_range
        use_range = (rng_start is not None and rng_end is not None)
        rng_span  = (rng_end - rng_start) if use_range else None

        @jax.jit
        def _gen(k):
            k1,k2 = jr.split(k)
            return k1, jr.randint(k2,(batch_sz*32,),0,256,dtype=jnp.uint8)

        rng = jr.PRNGKey(secrets.randbits(64))
        N   = SECP256K1_N
        while not stop_ev.is_set():
            rng, raw_jax = _gen(rng)
            raw = bytes(raw_jax.tolist())
            cnt = 0
            for i in range(batch_sz):
                if stop_ev.is_set(): break
                chunk = raw[i*32:(i+1)*32]
                if len(chunk)<32: continue
                ki = int.from_bytes(chunk,"big")
                if use_range:
                    ki = rng_start + (ki % (rng_span + 1))
                    chunk = ki.to_bytes(32, "big")
                else:
                    if not (0 < ki < N): continue
                addrs = derive_addresses(chunk)
                m     = check_match(addrs, targets)
                if m:
                    q.put({"privkey_hex":chunk.hex(),"addr_type":m[0],"addr":m[1],
                           "wif":addrs.get("wif",""),"all_addresses":addrs})
                    with counter.get_lock(): counter.value += cnt + 1
                    while not stop_ev.is_set(): time.sleep(0.05)
                    return
                cnt += 1
            with counter.get_lock(): counter.value += cnt
    except Exception as e:
        print(f"\n{Fore.RED}TPU error: {e} → CPU{Style.RESET_ALL}")
        _cpu_worker(0,counter,q,targets,stop_ev,1000,key_range)


# ==============================================================================
#  VERIFIKASI INDEPENDEN
# ==============================================================================

def verify(privkey_hex: str, target_addr: str) -> dict:
    v = {"ok":False,"matched_type":None,"pub_comp":None,"pub_uncomp":None,
         "derived":{},"notes":[]}
    try:
        kb = bytes.fromhex(privkey_hex)
        if not (0 < int.from_bytes(kb,"big") < SECP256K1_N):
            v["notes"].append("❌ Private key di luar range secp256k1!")
            return v
        addrs = derive_addresses(kb)
        if "_err" in addrs:
            v["notes"].append(f"❌ {addrs['_err']}"); return v

        # Dapatkan pubkey untuk info
        if _CCKey and BASE58_OK:
            pk = _CCKey(kb)
            v["pub_comp"]  = pk.public_key.format(True).hex()
            v["pub_uncomp"]= pk.public_key.format(False).hex()
        elif BIP_UTILS_OK:
            priv = Secp256k1PrivateKey.FromBytes(kb)
            v["pub_comp"]  = priv.PublicKey().RawCompressed().ToBytes().hex()
            v["pub_uncomp"]= priv.PublicKey().RawUncompressed().ToBytes().hex()

        v["derived"] = {k:val for k,val in addrs.items() if k not in ("wif","_err")}

        for at, av in addrs.items():
            if av and av == target_addr:
                v["ok"] = True; v["matched_type"] = at
                v["notes"].append(f"✅ VERIFIED  {at.upper()} → {av}")
                break
        if not v["ok"]:
            v["notes"].append("⚠  Re-derive TIDAK cocok — periksa race condition!")
    except Exception as e:
        v["notes"].append(f"❌ Error: {e}")
    return v


# ==============================================================================
#  DISPLAY & SAVE
# ==============================================================================

ADDR_META = {
    "p2pkh":        ("Legacy          (P2PKH)   [1...]   ", Fore.WHITE),
    "p2wpkh":       ("Native SegWit   (P2WPKH)  [bc1q...]", Fore.BLUE),
    "p2tr":         ("Taproot         (P2TR)    [bc1p...]", Fore.GREEN),
    "p2sh_p2wpkh":  ("Wrapped SegWit  (P2SH)   [3...]   ", Fore.YELLOW),
    "p2pkh_uncomp": ("Legacy Uncomp.  (P2PKH)   [1...]   ", Fore.WHITE),
}

def display_status(counter, t0, mode, nw, stop_ev, key_range=(None,None)):
    last = 0
    rng_start, rng_end = key_range
    use_range = (rng_start is not None and rng_end is not None)
    if use_range:
        span_bits = (rng_end - rng_start).bit_length()
        rng_label = f"Range:{Fore.MAGENTA}{span_bits}bit{Style.RESET_ALL} "
    else:
        rng_label = f"Range:{Fore.GREEN}FULL{Style.RESET_ALL} "
    while not stop_ev.is_set():
        time.sleep(1)
        now = time.time(); tot = counter.value
        spd = tot-last; last = tot
        avg = tot/(now-t0) if (now-t0)>0 else 0
        sys.stdout.write(
            f"\r[{Fore.CYAN}{mode}{Style.RESET_ALL}|"
            f"W:{Fore.GREEN}{nw}{Style.RESET_ALL}] "
            f"{rng_label}"
            f"Dicek:{Fore.YELLOW}{tot:,}{Style.RESET_ALL} "
            f"Speed:{Fore.GREEN}{spd:,}/s{Style.RESET_ALL} "
            f"Avg:{Fore.BLUE}{int(avg):,}/s{Style.RESET_ALL} "
            f"Waktu:{Fore.MAGENTA}{int(now-t0)}s{Style.RESET_ALL}    "
        ); sys.stdout.flush()

def display_and_save(result, cfg, found_file=FOUND_FILE):
    pk   = result["privkey_hex"]
    addr = result["addr"]
    ts   = time.strftime("%Y-%m-%d %H:%M:%S")
    wif  = result.get("wif","N/A")

    print(f"\n\n{'='*72}")
    print(f"{Fore.GREEN}{'🎉  KECOCOKAN DITEMUKAN!':^72}{Style.RESET_ALL}")
    print(f"{'='*72}")
    print(f"\n{Fore.CYAN}⏳ Verifikasi independen...{Style.RESET_ALL}")
    v = verify(pk, addr)
    vs = f"{Fore.GREEN}✅ VERIFIED{Style.RESET_ALL}" if v["ok"] else f"{Fore.RED}❌ GAGAL{Style.RESET_ALL}"
    print(f"   Status    : {vs}")
    for note in v["notes"]: print(f"   {note}")

    print(f"\n{'─'*72}")
    print(f"{Fore.YELLOW}  PRIVATE KEY{Style.RESET_ALL}")
    print(f"{'─'*72}")
    print(f"  {Fore.WHITE}HEX        :{Style.RESET_ALL} {Fore.RED}{pk}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}WIF        :{Style.RESET_ALL} {Fore.RED}{wif}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}PubKey (C) :{Style.RESET_ALL} {v.get('pub_comp','N/A')}")
    print(f"  {Fore.WHITE}PubKey (U) :{Style.RESET_ALL} {v.get('pub_uncomp','N/A')}")

    print(f"\n{'─'*72}")
    print(f"{Fore.YELLOW}  ALAMAT TARGET  [{result['addr_type'].upper()}]{Style.RESET_ALL}")
    print(f"{'─'*72}")
    lbl,col = ADDR_META.get(result["addr_type"],(result["addr_type"],Fore.WHITE))
    vmk = f"{Fore.GREEN}[✅ VERIFIED]{Style.RESET_ALL}" if v["ok"] else f"{Fore.RED}[❓]{Style.RESET_ALL}"
    print(f"  {col}{lbl}{Style.RESET_ALL}: {Fore.CYAN}{addr}{Style.RESET_ALL}  {vmk}")

    print(f"\n{'─'*72}")
    print(f"{Fore.YELLOW}  SEMUA ALAMAT DARI PRIVATE KEY INI{Style.RESET_ALL}")
    print(f"{'─'*72}")
    derived = v.get("derived", result.get("all_addresses",{}))
    for key,(label,color) in ADDR_META.items():
        val = derived.get(key)
        if val:
            mk = f"  {Fore.GREEN}◄ TARGET COCOK{Style.RESET_ALL}" if val==addr else ""
            print(f"  {color}{label}{Style.RESET_ALL}: {val}{mk}")
    print(f"\n{'='*72}\n")

    # ── Simpan found.txt ──────────────────────────────────────────────────────
    sep=72*"="; dsh=72*"-"
    lines=[
        "",sep,"  🎉 KECOCOKAN DITEMUKAN",
        f"  Waktu       : {ts}",
        f"  Akselerator : {ACCEL_TYPE} — {ACCEL_NAME}",
        f"  Crypto lib  : {CRYPTO}",
        sep,"",dsh,"  VERIFIKASI",dsh,
        f"  Status      : {'✅ VERIFIED' if v['ok'] else '❌ GAGAL'}",
        f"  Tipe Cocok  : {(v['matched_type'] or '').upper()}",
    ]
    for note in v["notes"]: lines.append(f"  {note}")
    lines+=[
        "",dsh,"  PRIVATE KEY",dsh,
        f"  HEX         : {pk}",
        f"  WIF         : {wif}",
        f"  PubKey (C)  : {v.get('pub_comp','N/A')}",
        f"  PubKey (U)  : {v.get('pub_uncomp','N/A')}",
        "",dsh,"  ALAMAT TARGET",dsh,
        f"  Tipe        : {result['addr_type'].upper()}",
        f"  Alamat      : {addr}",
        "",dsh,"  SEMUA ALAMAT",dsh,
    ]
    for key,(label,_) in ADDR_META.items():
        val = derived.get(key)
        if val:
            mk = "  ◄◄◄ TARGET COCOK" if val==addr else ""
            lines.append(f"  {label}: {val}{mk}")
    lines+=["",sep,""]
    with open(found_file,"a",encoding="utf-8") as f:
        f.write("\n".join(lines)+"\n")
    print(f"{Fore.GREEN}💾 Disimpan → {Fore.CYAN}{found_file}{Style.RESET_ALL}\n")

    # Telegram
    tg_notify(cfg, result, v, found_file)


# ==============================================================================
#  BANNER & SETUP
# ==============================================================================

def print_banner(targets_count: int, target_files: list, cpu_only=False):
    _LABEL = {
        "GPU_NVIDIA":"NVIDIA CUDA  ","GPU_AMD":"AMD ROCm     ",
        "GPU_INTEL":"Intel IPEX   ","GPU_APPLE":"Apple MPS    ",
        "TPU_JAX":"Google TPU   ","CPU":"CPU          ",
    }
    _COLOR = {
        "GPU_NVIDIA":Fore.GREEN,"GPU_AMD":Fore.RED,"GPU_INTEL":Fore.BLUE,
        "GPU_APPLE":Fore.WHITE,"TPU_JAX":Fore.CYAN,"CPU":Fore.WHITE,
    }
    c = _COLOR.get(ACCEL_TYPE,Fore.WHITE)
    l = _LABEL.get(ACCEL_TYPE,ACCEL_TYPE)
    crypto_color = Fore.GREEN if CRYPTO=="coincurve" else Fore.YELLOW
    crypto_note  = "(C-lib, cepat)" if CRYPTO=="coincurve" else "(Python, lambat — install coincurve!)"

    tfiles_str = "\n".join(f"     {Fore.CYAN}{tf}{Style.RESET_ALL}" for tf in target_files)

    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║    BITCOIN RICH HUNTER  ·  MAXIMUM PERFORMANCE EDITION              ║
║  GPU Universal · TPU · CPU Multi-core · Telegram · .gz Support       ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

  Akselerator : {c}{ACCEL_NAME}  [{l}]{Style.RESET_ALL}
  Crypto lib  : {crypto_color}{CRYPTO}  {crypto_note}{Style.RESET_ALL}
  Address types: P2PKH · P2WPKH · P2TR(Taproot) · P2SH · P2PKH-Uncomp

  Target files:
{tfiles_str}
  Total target : {Fore.YELLOW}{targets_count:,} alamat unik{Style.RESET_ALL}
""")

def select_cores() -> int:
    total = multiprocessing.cpu_count()
    opts  = sorted(set(c for c in [1,2,4,8,16,total] if c<=total))
    print(f"\n{Fore.YELLOW}Pilih jumlah CPU Core:{Style.RESET_ALL}")
    for i,c in enumerate(opts,1):
        tag = f"  {Fore.CYAN}← semua core{Style.RESET_ALL}" if c==total else ""
        print(f"  {Fore.CYAN}[{i}]{Style.RESET_ALL} {c} core{tag}")
    while True:
        try:
            idx = int(input(f"\n{Fore.WHITE}Pilihan (1-{len(opts)}): {Style.RESET_ALL}").strip())-1
            if 0<=idx<len(opts): return opts[idx]
        except (ValueError,KeyboardInterrupt): pass
        print(f"{Fore.RED}Tidak valid.{Style.RESET_ALL}")

def setup_telegram(cfg) -> dict:
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════╗
║  SETUP TELEGRAM BOT                            ║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
  1. Buka Telegram → @BotFather → /newbot → dapat TOKEN
  2. Kirim pesan ke bot Anda
  3. Buka: https://api.telegram.org/bot<TOKEN>/getUpdates
     Cari "chat":{{"id": ANGKA}} → itu CHAT_ID
""")
    token   = input(f"{Fore.WHITE}BOT TOKEN  : {Style.RESET_ALL}").strip()
    chat_id = input(f"{Fore.WHITE}CHAT ID    : {Style.RESET_ALL}").strip()
    sf      = input(f"{Fore.WHITE}Kirim found.txt? (y/n) [y]: {Style.RESET_ALL}").strip().lower()
    cfg["telegram"].update({"enabled":True,"bot_token":token,
                            "chat_id":chat_id,"send_file":(sf!="n")})
    with open(CONFIG_FILE,"w") as f: json.dump(cfg,f,indent=4)
    print(f"{Fore.GREEN}✅ Disimpan ke {CONFIG_FILE}{Style.RESET_ALL}")
    return cfg


# ==============================================================================
#  MAIN
# ==============================================================================

def main():
    if not (BIP_UTILS_OK or (CRYPTO=="coincurve")):
        print(f"{Fore.RED}❌ Tidak ada library kriptografi!\n   pip install coincurve bip_utils base58{Style.RESET_ALL}")
        sys.exit(1)

    if CRYPTO == "bip_utils":
        print(f"{Fore.YELLOW}⚠  coincurve tidak terinstall — performa tidak maksimal!")
        print(f"   Install: pip install coincurve base58{Style.RESET_ALL}")

    cfg = load_config()

    # ── Setup Telegram ────────────────────────────────────────────────────────
    tg = cfg["telegram"]
    if not tg["enabled"]:
        ans = input(f"\n{Fore.CYAN}Aktifkan notifikasi Telegram? (y/n): {Style.RESET_ALL}").strip().lower()
        if ans == "y": cfg = setup_telegram(cfg)
    elif tg["bot_token"].startswith("ISI_"):
        print(f"{Fore.YELLOW}⚠  Telegram diaktifkan tapi belum dikonfigurasi.{Style.RESET_ALL}")
        ans = input(f"{Fore.CYAN}Setup sekarang? (y/n): {Style.RESET_ALL}").strip().lower()
        if ans == "y": cfg = setup_telegram(cfg)

    # ── Deteksi akselerator ───────────────────────────────────────────────────
    detect_accel()

    # ── Load targets (dari semua file yang ada) ───────────────────────────────
    target_files_cfg = cfg.get("targets", ["btc.txt"])
    # Argumen CLI override
    if len(sys.argv) > 1:
        target_files_cfg = list(sys.argv[1:])

    all_targets  = set()
    loaded_files = []
    for tf in target_files_cfg:
        t = load_targets(tf)
        if t:
            all_targets.update(t)
            loaded_files.append(tf)

    if not all_targets:
        print(f"{Fore.RED}⚠  Tidak ada target alamat!{Style.RESET_ALL}")
        sys.exit(1)

    targets = frozenset(all_targets)
    found_file = cfg.get("found_file", FOUND_FILE)

    # ── Banner ────────────────────────────────────────────────────────────────
    print_banner(len(targets), loaded_files)

    # ── Pilih jumlah workers ──────────────────────────────────────────────────
    cpu_only    = (ACCEL_TYPE == "CPU")
    num_workers = 1
    mode_str    = ACCEL_TYPE

    if cpu_only:
        num_workers = select_cores()
        mode_str    = f"CPU×{num_workers}"
        print(f"\n{Fore.GREEN}✅ CPU {num_workers} core{Style.RESET_ALL}\n")
    else:
        # GPU/TPU: 1 akselerator worker + boleh tambah CPU worker jika user mau
        print(f"{Fore.GREEN}🚀 {ACCEL_TYPE}: {ACCEL_NAME}{Style.RESET_ALL}")
        ans = input(f"{Fore.CYAN}Tambah CPU workers untuk hybrid mode? (y/n): {Style.RESET_ALL}").strip().lower()
        if ans == "y":
            extra = select_cores()
            num_workers = extra
            mode_str = f"{ACCEL_TYPE}+CPU×{extra}"
        print()

    # ── Pilih Key Range ───────────────────────────────────────────────────────
    key_range = select_key_range()
    rng_start, rng_end = key_range
    if rng_start is not None:
        span_bits = (rng_end - rng_start).bit_length()
        print(f"\n  {Fore.CYAN}🔑 Key Range aktif  — span {span_bits}-bit{Style.RESET_ALL}")
        print(f"     Start : {Fore.YELLOW}{hex(rng_start)}{Style.RESET_ALL}")
        print(f"     End   : {Fore.YELLOW}{hex(rng_end)}{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.CYAN}🔑 Key Range: Full secp256k1 (random){Style.RESET_ALL}")
    print()

    # ── Test Telegram ─────────────────────────────────────────────────────────
    if tg.get("enabled") and not tg["bot_token"].startswith("ISI_"):
        print(f"{Fore.CYAN}📡 Test koneksi Telegram...{Style.RESET_ALL}")
        tg_test(cfg)

    print(f"\n{Fore.WHITE}Mulai mencari ... Ctrl+C untuk berhenti{Style.RESET_ALL}\n")
    time.sleep(0.5)

    counter    = Value(ctypes.c_uint64, 0)
    found_q    = Queue()
    stop_ev    = multiprocessing.Event()
    procs      = []
    t0         = time.time()
    gpu_batch  = cfg.get("gpu_batch", 8192)
    cpu_batch  = cfg.get("cpu_batch", 1000)

    def start_workers():
        ps = []
        # GPU/TPU worker
        if ACCEL_TYPE == "TPU_JAX":
            p = Process(target=_tpu_worker,
                        args=(counter,found_q,targets,stop_ev,gpu_batch,key_range))
            p.start(); ps.append(p)
        elif ACCEL_TYPE in ("GPU_NVIDIA","GPU_AMD","GPU_INTEL","GPU_APPLE"):
            bk, dev = ACCEL_BACKEND
            p = Process(target=_gpu_worker,
                        args=(counter,found_q,targets,stop_ev,bk,dev,gpu_batch,key_range))
            p.start(); ps.append(p)
        # CPU workers (tambahan atau utama)
        for i in range(num_workers if cpu_only else (num_workers if num_workers>1 else 0)):
            p = Process(target=_cpu_worker,
                        args=(i,counter,found_q,targets,stop_ev,cpu_batch,key_range))
            p.start(); ps.append(p)
        return ps

    try:
        procs = start_workers()
        threading.Thread(
            target=display_status,
            args=(counter,t0,mode_str,len(procs),stop_ev,key_range),
            daemon=True
        ).start()

        while True:
            if not found_q.empty():
                res = found_q.get()
                stop_ev.set()
                display_and_save(res, cfg, found_file)
                ans = input(f"{Fore.CYAN}Lanjut mencari? (y/n): {Style.RESET_ALL}").strip().lower()
                if ans == "y":
                    for p in procs: p.terminate()
                    procs.clear(); stop_ev.clear()
                    counter.value = 0; t0 = time.time()
                    procs = start_workers()
                    threading.Thread(
                        target=display_status,
                        args=(counter,t0,mode_str,len(procs),stop_ev,key_range),
                        daemon=True
                    ).start()
                else:
                    break
            time.sleep(0.1)

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⏹  Dihentikan.{Style.RESET_ALL}")
    finally:
        stop_ev.set()
        for p in procs: p.terminate(); p.join(timeout=2)
        elapsed = time.time()-t0; tot = counter.value
        avg = tot/elapsed if elapsed>0 else 0
        print(f"\n{Fore.CYAN}📊 Statistik Akhir{Style.RESET_ALL}")
        print(f"   Akselerator : {Fore.CYAN}{ACCEL_TYPE} — {ACCEL_NAME}{Style.RESET_ALL}")
        print(f"   Crypto lib  : {Fore.GREEN if CRYPTO=='coincurve' else Fore.YELLOW}{CRYPTO}{Style.RESET_ALL}")
        print(f"   Total Dicek : {Fore.YELLOW}{tot:,}{Style.RESET_ALL}")
        print(f"   Waktu       : {Fore.BLUE}{elapsed:.1f}s{Style.RESET_ALL}")
        print(f"   Rata-rata   : {Fore.GREEN}{int(avg):,}/s{Style.RESET_ALL}")
        print(f"\n{Fore.WHITE}Selesai.{Style.RESET_ALL}")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
