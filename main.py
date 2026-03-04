#!/usr/bin/env python3
# ==============================================================================
#  Bitcoin Rich Hunter — MAXIMUM PERFORMANCE EDITION (FIXED + IMPROVED FLOW)
#  -----------------------------------------------------------------------------
#  FEATURES:
#  ✅ Multi GPU (NVIDIA/AMD/Intel/Apple) – all GPUs used in parallel
#  ✅ Multi TPU (Google TPU) – each TPU core runs its own worker
#  ✅ Multi CPU – choose number of CPU cores (hybrid with GPU/TPU)
#  ✅ Puzzle range – select private key range (from puzzle list or custom)
#  ✅ Automatic device detection + interactive selection
#  ✅ Fallback to CPU if device initialisation fails
#  ✅ Telegram notifications + found.txt
#  ✅ Target files .txt or .gz (streaming)
#  ✅ Fast cryptography with coincurve (C bindings)
# ==============================================================================

import os
import sys
import re
import gzip
import time
import json
import secrets
import hashlib
import ctypes
import subprocess
import multiprocessing
from multiprocessing import Process, Value, Queue
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

from colorama import Fore, Style, init as colorama_init
colorama_init()

# ------------------------------------------------------------------------------
#  Cryptography libraries (with fallbacks)
# ------------------------------------------------------------------------------
try:
    from coincurve import PrivateKey as _CCKey
    CRYPTO_LIB = "coincurve"
except ImportError:
    _CCKey = None
    CRYPTO_LIB = "bip_utils"

try:
    from bip_utils import (
        WifEncoder, P2PKHAddrEncoder, P2WPKHAddrEncoder,
        P2TRAddrEncoder, P2SHAddrEncoder, Secp256k1PrivateKey,
    )
    BIP_UTILS_AVAILABLE = True
except ImportError:
    BIP_UTILS_AVAILABLE = False

try:
    import base58 as _b58
    BASE58_AVAILABLE = True
except ImportError:
    BASE58_AVAILABLE = False

if CRYPTO_LIB == "coincurve" and not BASE58_AVAILABLE:
    print(f"{Fore.YELLOW}⚠️  coincurve needs base58 – falling back to bip_utils{Style.RESET_ALL}")
    CRYPTO_LIB = "bip_utils"

SECP256K1_N = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
CONFIG_FILE = "config.json"
FOUND_FILE = "found.txt"

# ------------------------------------------------------------------------------
#  Fast cryptography helpers (used by both coincurve and bip_utils)
# ------------------------------------------------------------------------------
def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def _ripemd160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()

def _hash160(data: bytes) -> bytes:
    return _ripemd160(_sha256(data))

def _b58check(payload: bytes) -> str:
    checksum = _sha256(_sha256(payload))[:4]
    return _b58.b58encode(payload + checksum).decode()

# --- Bech32 / Bech32m encoder (native implementation) ---
_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk

def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _convert_bits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def _encode_bech32(hrp, witver, witprog, bech32m=False):
    values = _convert_bits([witver] + list(witprog), 8, 5)
    const = 0x2bc830a3 if bech32m else 1
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + values + [0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_ALPHABET[x] for x in values + checksum)

def _p2wpkh(h160: bytes) -> str:
    return _encode_bech32("bc", 0, h160)

def _p2tr(xonly: bytes) -> str:
    return _encode_bech32("bc", 1, xonly, bech32m=True)

def _taproot_tweak(pubkey_compressed: bytes) -> bytes:
    """BIP341 key-path tweak: Q = P + H_tapTweak(P)*G"""
    xonly = pubkey_compressed[1:]
    tag = b"TapTweak"
    tweak_hash = _sha256(tag + tag + xonly)
    if _CCKey:
        try:
            from coincurve import PublicKey as _CCPub
            q = _CCPub(pubkey_compressed).add(tweak_hash)
            return q.format(compressed=True)[1:]   # return x-only
        except Exception:
            pass
    return xonly   # fallback: untweaked x-only

def derive_addresses(privkey_bytes: bytes) -> Dict[str, Optional[str]]:
    """
    Derive all common Bitcoin address types from a private key.
    Uses coincurve if available (fast), otherwise bip_utils.
    """
    result = {}
    try:
        if _CCKey and BASE58_AVAILABLE:
            # ---------- coincurve (C library, fast) ----------
            pk = _CCKey(privkey_bytes)
            pub_comp = pk.public_key.format(compressed=True)    # 33 bytes
            pub_uncomp = pk.public_key.format(compressed=False) # 65 bytes

            h160_comp = _hash160(pub_comp)
            h160_uncomp = _hash160(pub_uncomp)

            # WIF (compressed)
            result["wif"] = _b58check(b"\x80" + privkey_bytes + b"\x01")

            # P2PKH (compressed)
            result["p2pkh"] = _b58check(b"\x00" + h160_comp)
            # P2PKH (uncompressed)
            result["p2pkh_uncomp"] = _b58check(b"\x00" + h160_uncomp)
            # P2WPKH (native segwit)
            result["p2wpkh"] = _p2wpkh(h160_comp)
            # P2SH-P2WPKH (wrapped segwit)
            redeem_script = b"\x00\x14" + h160_comp
            result["p2sh_p2wpkh"] = _b58check(b"\x05" + _hash160(redeem_script))
            # P2TR (taproot)
            try:
                result["p2tr"] = _p2tr(_taproot_tweak(pub_comp))
            except Exception:
                result["p2tr"] = None

        elif BIP_UTILS_AVAILABLE:
            # ---------- bip_utils (pure Python fallback) ----------
            priv = Secp256k1PrivateKey.FromBytes(privkey_bytes)
            pub = priv.PublicKey()
            pub_comp = pub.RawCompressed().ToBytes()
            pub_uncomp = pub.RawUncompressed().ToBytes()

            result["wif"] = WifEncoder.Encode(priv.Raw().ToBytes(), True)
            result["p2pkh"] = P2PKHAddrEncoder.EncodeKey(pub_comp)
            result["p2wpkh"] = P2WPKHAddrEncoder.EncodeKey(pub_comp)
            result["p2sh_p2wpkh"] = P2SHAddrEncoder.EncodeKey(pub_comp)
            result["p2pkh_uncomp"] = P2PKHAddrEncoder.EncodeKey(pub_uncomp)
            try:
                result["p2tr"] = P2TRAddrEncoder.EncodeKey(pub_comp)
            except Exception:
                result["p2tr"] = None
        else:
            result["_error"] = "No cryptography library available!"
    except Exception as e:
        result["_error"] = str(e)
    return result

def check_match(addresses: Dict[str, Optional[str]], targets: Set[str]) -> Optional[Tuple[str, str]]:
    """Return (address_type, address) if any derived address is in targets."""
    for addr_type, addr in addresses.items():
        if addr and addr in targets:
            return addr_type, addr
    return None

# ------------------------------------------------------------------------------
#  Load target addresses from .txt or .gz (streaming)
# ------------------------------------------------------------------------------
def load_targets(path: str) -> Set[str]:
    """Load Bitcoin addresses from a text file or gzipped file."""
    p = Path(path)
    if not p.exists():
        print(f"{Fore.RED}❌ File not found: {path}{Style.RESET_ALL}")
        if path.endswith(".gz"):
            print(f"{Fore.YELLOW}   Download from: http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz{Style.RESET_ALL}")
        else:
            # Create a template
            with open(path, "w") as f:
                f.write("# One Bitcoin address per line\n")
                f.write("# 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n")
            print(f"{Fore.YELLOW}   Template created: {path}{Style.RESET_ALL}")
        return set()

    size_mb = p.stat().st_size / (1024 * 1024)
    is_gz = path.endswith(".gz")

    print(f"{Fore.CYAN}📂 Loading {path}  ({size_mb:.1f} MB){Style.RESET_ALL}")
    if is_gz:
        print(f"   {Fore.YELLOW}Mode: streaming gz (no extraction needed){Style.RESET_ALL}")
    print("   Please wait...", end="", flush=True)

    t0 = time.time()
    addresses = set()

    try:
        opener = gzip.open(path, "rt", encoding="ascii", errors="ignore") if is_gz else open(path, "r", encoding="ascii", errors="ignore")
        with opener as f:
            for line in f:
                addr = line.strip()
                if addr and not addr.startswith("#") and addr[0] in "13b":
                    addresses.add(addr)
                    if len(addresses) % 5_000_000 == 0:
                        print(f"\r   {Fore.GREEN}{len(addresses)/1e6:.1f}M{Style.RESET_ALL} addresses loaded...", end="", flush=True)
    except Exception as e:
        print(f"\n{Fore.RED}❌ Error reading file: {e}{Style.RESET_ALL}")
        return set()

    elapsed = time.time() - t0
    print(f"\r   {Fore.GREEN}✅ {len(addresses):,} unique addresses loaded in {elapsed:.1f}s{Style.RESET_ALL}")
    return addresses

# ------------------------------------------------------------------------------
#  Configuration
# ------------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "telegram": {
        "enabled": False,
        "bot_token": "YOUR_BOT_TOKEN",
        "chat_id": "YOUR_CHAT_ID",
        "send_file": True
    },
    "targets": [
        "btc.txt",
        "Bitcoin_addresses_LATEST.txt.gz"
    ],
    "found_file": "found.txt",
    "gpu_batch": 8192,
    "cpu_batch": 1000
}

def load_config() -> Dict:
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        print(f"{Fore.YELLOW}⚙  config.json created.{Style.RESET_ALL}")
        return DEFAULT_CONFIG.copy()
    with open(CONFIG_FILE) as f:
        cfg = json.load(f)
    # Merge with defaults
    for k, v in DEFAULT_CONFIG.items():
        if k not in cfg:
            cfg[k] = v
        elif isinstance(v, dict):
            for k2, v2 in v.items():
                if k2 not in cfg[k]:
                    cfg[k][k2] = v2
    return cfg

# ------------------------------------------------------------------------------
#  Puzzle range selection
# ------------------------------------------------------------------------------
# Puzzle ranges (from https://privatekeys.info/puzzle/ and others)
PUZZLE_RANGES = [
    ("#71  — 71-bit", 0x400000000000000000, 0x7FFFFFFFFFFFFFFFFF, 71),
    ("#72  — 72-bit", 0x800000000000000000, 0xFFFFFFFFFFFFFFFFFF, 72),
    ("#73  — 73-bit", 0x1000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFF, 73),
    ("#74  — 74-bit", 0x2000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFF, 74),
    ("#76  — 76-bit", 0x8000000000000000000, 0xFFFFFFFFFFFFFFFFFFFF, 76),
    ("#77  — 77-bit", 0x10000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFF, 77),
    ("#78  — 78-bit", 0x20000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFF, 78),
    ("#79  — 79-bit", 0x40000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFF, 79),
    ("#81  — 81-bit", 0x100000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFF, 81),
    ("#82  — 82-bit", 0x200000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFF, 82),
    ("#83  — 83-bit", 0x400000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFF, 83),
    ("#84  — 84-bit", 0x800000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFF, 84),
    ("#86  — 86-bit", 0x2000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFF, 86),
    ("#87  — 87-bit", 0x4000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFF, 87),
    ("#88  — 88-bit", 0x8000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFF, 88),
    ("#89  — 89-bit", 0x10000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFF, 89),
    ("#91  — 91-bit", 0x40000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFF, 91),
    ("#92  — 92-bit", 0x80000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 92),
    ("#93  — 93-bit", 0x100000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFF, 93),
    ("#94  — 94-bit", 0x200000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFF, 94),
    ("#96  — 96-bit", 0x800000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 96),
    ("#97  — 97-bit", 0x1000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 97),
    ("#98  — 98-bit", 0x2000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 98),
    ("#99  — 99-bit", 0x4000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 99),
    ("#101 — 101-bit", 0x10000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 101),
    ("#102 — 102-bit", 0x20000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 102),
    ("#103 — 103-bit", 0x40000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 103),
    ("#104 — 104-bit", 0x80000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 104),
    ("#106 — 106-bit", 0x200000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 106),
    ("#107 — 107-bit", 0x400000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 107),
    ("#108 — 108-bit", 0x800000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 108),
    ("#109 — 109-bit", 0x1000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 109),
    ("#111 — 111-bit", 0x4000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 111),
    ("#112 — 112-bit", 0x8000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 112),
    ("#113 — 113-bit", 0x10000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 113),
    ("#114 — 114-bit", 0x20000000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 114),
    ("#116 — 116-bit", 0x80000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 116),
    ("#117 — 117-bit", 0x100000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 117),
    ("#118 — 118-bit", 0x200000000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 118),
    ("#119 — 119-bit", 0x400000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 119),
    ("#121 — 121-bit", 0x1000000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 121),
    ("#122 — 122-bit", 0x2000000000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 122),
    ("#123 — 123-bit", 0x4000000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 123),
    ("#124 — 124-bit", 0x8000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 124),
    ("#126 — 126-bit", 0x20000000000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 126),
    ("#127 — 127-bit", 0x40000000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 127),
    ("#128 — 128-bit", 0x80000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 128),
    ("#129 — 129-bit", 0x100000000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 129),
    ("#131 — 131-bit", 0x400000000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 131),
    ("#132 — 132-bit", 0x800000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 132),
    ("#133 — 133-bit", 0x1000000000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 133),
    ("#134 — 134-bit", 0x2000000000000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 134),
    ("#135 — 135-bit", 0x4000000000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 135),
    ("#136 — 136-bit", 0x8000000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 136),
    ("#137 — 137-bit", 0x10000000000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 137),
    ("#138 — 138-bit", 0x20000000000000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 138),
    ("#139 — 139-bit", 0x40000000000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 139),
    ("#140 — 140-bit", 0x80000000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 140),
    ("#141 — 141-bit", 0x100000000000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 141),
    ("#142 — 142-bit", 0x200000000000000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 142),
    ("#143 — 143-bit", 0x400000000000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 143),
    ("#144 — 144-bit", 0x800000000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 144),
    ("#145 — 145-bit", 0x1000000000000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 145),
    ("#146 — 146-bit", 0x2000000000000000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 146),
    ("#147 — 147-bit", 0x4000000000000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 147),
    ("#148 — 148-bit", 0x8000000000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 148),
    ("#149 — 149-bit", 0x10000000000000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 149),
    ("#150 — 150-bit", 0x20000000000000000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 150),
    ("#151 — 151-bit", 0x40000000000000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 151),
    ("#152 — 152-bit", 0x80000000000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 152),
    ("#153 — 153-bit", 0x100000000000000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 153),
    ("#154 — 154-bit", 0x200000000000000000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 154),
    ("#155 — 155-bit", 0x400000000000000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 155),
    ("#156 — 156-bit", 0x800000000000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 156),
    ("#157 — 157-bit", 0x1000000000000000000000000000000000000000, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 157),
    ("#158 — 158-bit", 0x2000000000000000000000000000000000000000, 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 158),
    ("#159 — 159-bit", 0x4000000000000000000000000000000000000000, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 159),
    ("#160 — 160-bit", 0x8000000000000000000000000000000000000000, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 160),  # truncated to stay below N
    ("Custom — Enter your own range", None, None, 0),
    ("Full  — The entire secp256k1 range (random)", None, None, -1),
]

def select_puzzle_range() -> Tuple[Optional[int], Optional[int], str]:
    """Let user choose a puzzle range or custom range."""
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════╗")
    print(f"║  SELECT PRIVATE KEY RANGE                         ║")
    print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
    for i, (desc, lo, hi, bits) in enumerate(PUZZLE_RANGES, 1):
        if lo is None:
            print(f"  {Fore.CYAN}[{i}]{Style.RESET_ALL} {desc}")
        else:
            print(f"  {Fore.CYAN}[{i}]{Style.RESET_ALL} {desc}  ({hex(lo)} ... {hex(hi)})")
    while True:
        try:
            choice = int(input(f"\n{Fore.WHITE}Choice (1-{len(PUZZLE_RANGES)}): {Style.RESET_ALL}").strip())
            if 1 <= choice <= len(PUZZLE_RANGES):
                break
        except ValueError:
            pass
        print(f"{Fore.RED}Invalid input.{Style.RESET_ALL}")
    desc, lo, hi, bits = PUZZLE_RANGES[choice - 1]
    if bits == -1:   # full range
        return None, None, desc
    if bits == 0:    # custom
        print(f"\n{Fore.YELLOW}Enter your own range (hex, without '0x'):{Style.RESET_ALL}")
        lo_hex = input("  Min (hex): ").strip()
        hi_hex = input("  Max (hex): ").strip()
        try:
            lo = int(lo_hex, 16) if lo_hex else None
            hi = int(hi_hex, 16) if hi_hex else None
            if lo is None or hi is None:
                print(f"{Fore.RED}Invalid range.{Style.RESET_ALL}")
                return select_puzzle_range()
            if lo >= hi:
                print(f"{Fore.RED}Min must be less than Max.{Style.RESET_ALL}")
                return select_puzzle_range()
            if lo < 1 or hi >= SECP256K1_N:
                print(f"{Fore.RED}Range must be between 1 and {SECP256K1_N - 1}.{Style.RESET_ALL}")
                return select_puzzle_range()
        except ValueError:
            print(f"{Fore.RED}Invalid hex format.{Style.RESET_ALL}")
            return select_puzzle_range()
        return lo, hi, f"Custom ({hex(lo)} - {hex(hi)})"
    else:
        return lo, hi, desc

# ------------------------------------------------------------------------------
#  Telegram notifier
# ------------------------------------------------------------------------------
def _telegram_request(token: str, method: str, **kwargs) -> Dict:
    try:
        import requests
        url = f"https://api.telegram.org/bot{token}/{method}"
        resp = requests.post(url, timeout=30, **kwargs)
        return resp.json()
    except Exception as e:
        print(f"\n{Fore.RED}Telegram {method} error: {e}{Style.RESET_ALL}")
        return {}

def telegram_send_message(token: str, chat_id: str, text: str):
    _telegram_request(token, "sendMessage", json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"})

def telegram_send_file(token: str, chat_id: str, file_path: str, caption: str = ""):
    if not os.path.exists(file_path):
        return
    try:
        import requests
        with open(file_path, "rb") as f:
            requests.post(
                f"https://api.telegram.org/bot{token}/sendDocument",
                timeout=60,
                data={"chat_id": chat_id, "caption": caption},
                files={"document": f}
            )
    except Exception as e:
        print(f"\n{Fore.RED}Telegram file send error: {e}{Style.RESET_ALL}")

def telegram_notify(cfg: Dict, result: Dict, verification: Dict, found_file: str,
                    devices_str: str, range_desc: str):
    tg = cfg.get("telegram", {})
    if not tg.get("enabled"):
        return
    token = tg.get("bot_token", "")
    chat_id = tg.get("chat_id", "")
    if not token or token.startswith("YOUR_"):
        return

    privkey_hex = result["privkey_hex"]
    wif = result.get("wif", "N/A")
    addr = result["addr"]
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    verified_status = "✅ VERIFIED" if verification.get("ok") else "❓ UNVERIFIED"
    derived = verification.get("derived", {})

    rows = ""
    for key, label in [
        ("p2pkh", "P2PKH [1...]"),
        ("p2wpkh", "P2WPKH [bc1q...]"),
        ("p2tr", "P2TR [bc1p...]"),
        ("p2sh_p2wpkh", "P2SH [3...]"),
        ("p2pkh_uncomp", "P2PKH-U [1...]")
    ]:
        val = derived.get(key)
        if val:
            marker = " ◄" if val == addr else ""
            rows += f"\n<code>{label}: {val}{marker}</code>"

    msg = (
        f"🎉 <b>BITCOIN FOUND!</b>\n"
        f"🕐 {timestamp}\n"
        f"🖥 {devices_str}\n"
        f"📊 Range: {range_desc}\n"
        f"{verified_status}\n\n"
        f"🔑 <b>PRIVATE KEY</b>\n"
        f"HEX: <code>{privkey_hex}</code>\n"
        f"WIF: <code>{wif}</code>\n\n"
        f"🎯 <b>TARGET [{result['addr_type'].upper()}]</b>\n"
        f"<code>{addr}</code>\n\n"
        f"📋 <b>ALL ADDRESSES</b>{rows}"
    )

    print(f"\n{Fore.CYAN}📨 Sending Telegram message...{Style.RESET_ALL}")
    r = _telegram_request(token, "sendMessage", json={"chat_id": chat_id, "text": msg, "parse_mode": "HTML"})
    if r.get("ok"):
        print(f"  {Fore.GREEN}✅ Message sent{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}❌ Failed: {r}{Style.RESET_ALL}")

    if tg.get("send_file"):
        print(f"  {Fore.CYAN}📎 Sending {found_file} ...{Style.RESET_ALL}")
        telegram_send_file(token, chat_id, found_file, caption=f"found.txt — {timestamp}")
        print(f"  {Fore.GREEN}✅ File sent{Style.RESET_ALL}")

def telegram_test(cfg: Dict, devices_str: str, range_desc: str) -> bool:
    tg = cfg.get("telegram", {})
    if not tg.get("enabled"):
        return False
    token = tg.get("bot_token", "")
    chat_id = tg.get("chat_id", "")
    if not token or token.startswith("YOUR_"):
        return False
    r = _telegram_request(token, "getMe")
    if r.get("ok"):
        bot_name = r["result"].get("username", "")
        print(f"  {Fore.GREEN}✅ Telegram bot @{bot_name} connected{Style.RESET_ALL}")
        telegram_send_message(
            token, chat_id,
            f"🤖 <b>Bitcoin Hunter started</b>\n"
            f"⏰ {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"🖥 {devices_str}\n"
            f"📊 Range: {range_desc}\n"
            f"🔍 Searching..."
        )
        return True
    print(f"  {Fore.RED}❌ Telegram connection failed: {r}{Style.RESET_ALL}")
    return False

# ------------------------------------------------------------------------------
#  Hardware detection (GPU / TPU) using PyTorch and JAX
# ------------------------------------------------------------------------------
def _run_cmd(cmd: List[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:
        return ""

def detect_devices() -> List[Dict[str, Any]]:
    """
    Detect all available accelerators (GPU, TPU) using PyTorch and JAX.
    Returns a list of device dictionaries with keys: type, backend, device_id, name, api.
    """
    devices = []

    # ---------- NVIDIA / AMD (CUDA / ROCm) via PyTorch ----------
    try:
        import torch
        if torch.cuda.is_available():
            for i in range(torch.cuda.device_count()):
                name = torch.cuda.get_device_name(i)
                # crude AMD detection (ROCm devices often have "RADEON", "RX", etc. in name)
                if any(x in name.upper() for x in ["RADEON", "RX", "VEGA", "NAVI", "RDNA", "GFX"]):
                    dev_type = "amd"
                else:
                    dev_type = "nvidia"
                devices.append({
                    "type": dev_type,
                    "backend": "torch",
                    "device_id": i,
                    "name": name,
                    "api": "cuda"
                })
    except ImportError:
        pass

    # ---------- Intel GPU (XPU) via PyTorch + IPEX ----------
    try:
        import torch
        # import intel_extension_for_pytorch as ipex  # noqa
        if hasattr(torch, "xpu") and torch.xpu.is_available():
            for i in range(torch.xpu.device_count()):
                name = torch.xpu.get_device_name(i)
                devices.append({
                    "type": "intel",
                    "backend": "torch",
                    "device_id": i,
                    "name": name,
                    "api": "xpu"
                })
    except ImportError:
        pass

    # ---------- Apple Silicon (MPS) ----------
    if sys.platform == "darwin":
        try:
            import torch
            if torch.backends.mps.is_available():
                # MPS is a single device
                chip = _run_cmd(["sysctl", "-n", "machdep.cpu.brand_string"]) or "Apple Silicon"
                devices.append({
                    "type": "apple",
                    "backend": "torch",
                    "device_id": 0,
                    "name": chip,
                    "api": "mps"
                })
        except ImportError:
            pass

    # ---------- Google TPU (via JAX) ----------
    try:
        import jax
        # Try to get TPU devices
        tpu_devices = jax.devices("tpu")
        if tpu_devices:
            for i, dev in enumerate(tpu_devices):
                devices.append({
                    "type": "tpu",
                    "backend": "jax",
                    "device_id": i,
                    "name": str(dev).split("(")[0].strip(),
                    "api": None
                })
    except (ImportError, RuntimeError):
        # JAX not installed or no TPU
        pass

    return devices

# ------------------------------------------------------------------------------
#  Worker functions
# ------------------------------------------------------------------------------
def _cpu_worker(worker_id: int, counter: Value, found_queue: Queue,
                targets: Set[str], stop_event, batch_size: int,
                range_min: Optional[int], range_max: Optional[int]):
    """CPU worker that generates random private keys within the given range."""
    local_checked = 0
    N = SECP256K1_N
    if range_min is None:   # full range: any 32-byte value < N
        def generate_key() -> bytes:
            while True:
                k = secrets.token_bytes(32)
                if 0 < int.from_bytes(k, 'big') < N:
                    return k
    else:
        range_size = range_max - range_min + 1
        def generate_key() -> bytes:
            val = secrets.randbelow(range_size) + range_min
            return val.to_bytes(32, 'big')

    while not stop_event.is_set():
        key_bytes = generate_key()
        addresses = derive_addresses(key_bytes)
        match = check_match(addresses, targets)
        if match:
            found_queue.put({
                "privkey_hex": key_bytes.hex(),
                "addr_type": match[0],
                "addr": match[1],
                "wif": addresses.get("wif", ""),
                "all_addresses": addresses
            })
        local_checked += 1
        if local_checked >= batch_size:
            with counter.get_lock():
                counter.value += local_checked
            local_checked = 0

def _gpu_worker(device_info: Dict, counter: Value, found_queue: Queue,
                targets: Set[str], stop_event, batch_size: int,
                range_min: Optional[int], range_max: Optional[int]):
    """
    GPU worker using PyTorch (supports CUDA, ROCm, MPS, XPU).
    Falls back to CPU if initialisation fails.
    """
    dev_type = device_info["type"]
    backend = device_info["backend"]
    device_id = device_info["device_id"]
    api = device_info.get("api")
    N = SECP256K1_N

    # Try to initialise the device
    try:
        import torch
        if api == "cuda":
            torch.cuda.set_device(device_id)
            device = torch.device(f"cuda:{device_id}")
        elif api == "xpu":
            torch.xpu.set_device(device_id)
            device = torch.device(f"xpu:{device_id}")
        elif api == "mps":
            device = torch.device("mps")
        else:
            raise ValueError(f"Unsupported torch API: {api}")

        # Test device with a small tensor
        torch.randint(0, 256, (32,), dtype=torch.uint8, device=device).cpu()
        print(f"  {Fore.GREEN}✅ {dev_type.upper()} {device_id}: {device_info['name']} (PyTorch/{api}){Style.RESET_ALL}")

        def generate_batch(n: int) -> bytes:
            # Generate random bytes directly on the GPU
            rand_tensor = torch.randint(0, 256, (n * 32,), dtype=torch.uint8, device=device)
            return rand_tensor.cpu().numpy().tobytes()

    except Exception as e:
        print(f"\n{Fore.RED}❌ Failed to initialise {dev_type} {device_id}: {e} → falling back to CPU{Style.RESET_ALL}")
        # Fallback to CPU worker (with same worker_id = device_id)
        _cpu_worker(device_id, counter, found_queue, targets, stop_event, 1000, range_min, range_max)
        return

    # Main loop: generate batches, process, update counter
    local_checked = 0
    while not stop_event.is_set():
        raw_bytes = generate_batch(batch_size)
        for i in range(batch_size):
            if stop_event.is_set():
                break
            chunk = raw_bytes[i*32:(i+1)*32]
            if len(chunk) < 32:
                continue
            val = int.from_bytes(chunk, 'big')
            if range_min is not None and (val < range_min or val > range_max):
                continue
            if val == 0 or val >= N:
                continue
            addresses = derive_addresses(chunk)
            match = check_match(addresses, targets)
            if match:
                found_queue.put({
                    "privkey_hex": chunk.hex(),
                    "addr_type": match[0],
                    "addr": match[1],
                    "wif": addresses.get("wif", ""),
                    "all_addresses": addresses
                })
            local_checked += 1
            if local_checked >= batch_size:
                with counter.get_lock():
                    counter.value += local_checked
                local_checked = 0
    # Flush remaining count
    if local_checked > 0:
        with counter.get_lock():
            counter.value += local_checked

def _tpu_worker(device_info: Dict, counter: Value, found_queue: Queue,
                targets: Set[str], stop_event, batch_size: int,
                range_min: Optional[int], range_max: Optional[int]):
    """TPU worker using JAX (one process per TPU core)."""
    device_id = device_info["device_id"]
    N = SECP256K1_N

    try:
        import jax
        import jax.numpy as jnp
        import jax.random as jrand

        tpu_devices = jax.devices("tpu")
        if device_id >= len(tpu_devices):
            raise RuntimeError(f"TPU device {device_id} not available")
        dev = tpu_devices[device_id]

        # Set default device (JAX >=0.4)
        from jax import default_device
        with default_device(dev):
            @jax.jit
            def generate_batch(key):
                key1, key2 = jrand.split(key)
                return key1, jrand.randint(key2, (batch_size * 32,), 0, 256, dtype=jnp.uint8)

            rng = jrand.PRNGKey(secrets.randbits(64))
            print(f"  {Fore.GREEN}✅ TPU core {device_id}: {dev} active{Style.RESET_ALL}")

            local_checked = 0
            while not stop_event.is_set():
                rng, rand_tensor = generate_batch(rng)
                raw_bytes = bytes(rand_tensor.tolist())
                for i in range(batch_size):
                    if stop_event.is_set():
                        break
                    chunk = raw_bytes[i*32:(i+1)*32]
                    if len(chunk) < 32:
                        continue
                    val = int.from_bytes(chunk, 'big')
                    if range_min is not None and (val < range_min or val > range_max):
                        continue
                    if val == 0 or val >= N:
                        continue
                    addresses = derive_addresses(chunk)
                    match = check_match(addresses, targets)
                    if match:
                        found_queue.put({
                            "privkey_hex": chunk.hex(),
                            "addr_type": match[0],
                            "addr": match[1],
                            "wif": addresses.get("wif", ""),
                            "all_addresses": addresses
                        })
                    local_checked += 1
                    if local_checked >= batch_size:
                        with counter.get_lock():
                            counter.value += local_checked
                        local_checked = 0
            if local_checked > 0:
                with counter.get_lock():
                    counter.value += local_checked

    except Exception as e:
        print(f"\n{Fore.RED}❌ TPU core {device_id} error: {e} → falling back to CPU{Style.RESET_ALL}")
        _cpu_worker(device_id, counter, found_queue, targets, stop_event, 1000, range_min, range_max)

# ------------------------------------------------------------------------------
#  Verification (independent of worker)
# ------------------------------------------------------------------------------
def verify_private_key(privkey_hex: str, target_addr: str) -> Dict:
    """Re-derive all addresses from the private key and compare with the found target."""
    result = {
        "ok": False,
        "matched_type": None,
        "pub_compressed": None,
        "pub_uncompressed": None,
        "derived": {},
        "notes": []
    }
    try:
        key_bytes = bytes.fromhex(privkey_hex)
        key_int = int.from_bytes(key_bytes, 'big')
        if not (0 < key_int < SECP256K1_N):
            result["notes"].append("❌ Private key outside secp256k1 range!")
            return result

        addresses = derive_addresses(key_bytes)
        if "_error" in addresses:
            result["notes"].append(f"❌ {addresses['_error']}")
            return result

        if _CCKey and BASE58_AVAILABLE:
            pk = _CCKey(key_bytes)
            result["pub_compressed"] = pk.public_key.format(compressed=True).hex()
            result["pub_uncompressed"] = pk.public_key.format(compressed=False).hex()
        elif BIP_UTILS_AVAILABLE:
            priv = Secp256k1PrivateKey.FromBytes(key_bytes)
            result["pub_compressed"] = priv.PublicKey().RawCompressed().ToBytes().hex()
            result["pub_uncompressed"] = priv.PublicKey().RawUncompressed().ToBytes().hex()

        # Remove wif from derived addresses for cleaner output
        result["derived"] = {k: v for k, v in addresses.items() if k not in ("wif", "_error")}

        for at, av in addresses.items():
            if av and av == target_addr:
                result["ok"] = True
                result["matched_type"] = at
                result["notes"].append(f"✅ VERIFIED: {at.upper()} → {av}")
                break
        if not result["ok"]:
            result["notes"].append("⚠️  Re-derived addresses DO NOT match target! Possible race condition.")

    except Exception as e:
        result["notes"].append(f"❌ Verification error: {e}")
    return result

# ------------------------------------------------------------------------------
#  Display and save found key
# ------------------------------------------------------------------------------
ADDRESS_LABELS = {
    "p2pkh": ("Legacy (P2PKH) [1...]", Fore.WHITE),
    "p2wpkh": ("Native SegWit (P2WPKH) [bc1q...]", Fore.BLUE),
    "p2tr": ("Taproot (P2TR) [bc1p...]", Fore.GREEN),
    "p2sh_p2wpkh": ("Wrapped SegWit (P2SH) [3...]", Fore.YELLOW),
    "p2pkh_uncomp": ("Legacy Uncompressed (P2PKH) [1...]", Fore.WHITE),
}

def display_status(counter: Value, start_time: float, mode: str,
                   num_workers: int, stop_event):
    """Background thread to show progress."""
    last_count = 0
    while not stop_event.is_set():
        time.sleep(1)
        now = time.time()
        total = counter.value
        speed = total - last_count
        last_count = total
        avg = total / (now - start_time) if (now - start_time) > 0 else 0
        sys.stdout.write(
            f"\r[{Fore.CYAN}{mode}{Style.RESET_ALL}|"
            f"W:{Fore.GREEN}{num_workers}{Style.RESET_ALL}] "
            f"Checked:{Fore.YELLOW}{total:,}{Style.RESET_ALL} "
            f"Speed:{Fore.GREEN}{speed:,}/s{Style.RESET_ALL} "
            f"Avg:{Fore.BLUE}{int(avg):,}/s{Style.RESET_ALL} "
            f"Time:{Fore.MAGENTA}{int(now-start_time)}s{Style.RESET_ALL}    "
        )
        sys.stdout.flush()

def save_and_display(result: Dict, cfg: Dict, found_file: str,
                     devices_str: str, range_desc: str):
    """Show the found key details on screen and save to found.txt, then notify Telegram."""
    privkey_hex = result["privkey_hex"]
    addr = result["addr"]
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    wif = result.get("wif", "N/A")

    print(f"\n\n{'='*72}")
    print(f"{Fore.GREEN}{'🎉  MATCH FOUND!':^72}{Style.RESET_ALL}")
    print(f"{'='*72}")

    print(f"\n{Fore.CYAN}⏳ Independent verification...{Style.RESET_ALL}")
    verification = verify_private_key(privkey_hex, addr)
    verif_status = f"{Fore.GREEN}✅ VERIFIED{Style.RESET_ALL}" if verification["ok"] else f"{Fore.RED}❌ FAILED{Style.RESET_ALL}"
    print(f"   Status    : {verif_status}")
    for note in verification["notes"]:
        print(f"   {note}")

    print(f"\n{'─'*72}")
    print(f"{Fore.YELLOW}  PRIVATE KEY{Style.RESET_ALL}")
    print(f"{'─'*72}")
    print(f"  {Fore.WHITE}HEX        :{Style.RESET_ALL} {Fore.RED}{privkey_hex}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}WIF        :{Style.RESET_ALL} {Fore.RED}{wif}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}PubKey (C) :{Style.RESET_ALL} {verification.get('pub_compressed', 'N/A')}")
    print(f"  {Fore.WHITE}PubKey (U) :{Style.RESET_ALL} {verification.get('pub_uncompressed', 'N/A')}")

    print(f"\n{'─'*72}")
    print(f"{Fore.YELLOW}  TARGET ADDRESS  [{result['addr_type'].upper()}]{Style.RESET_ALL}")
    print(f"{'─'*72}")
    label, color = ADDRESS_LABELS.get(result["addr_type"], (result["addr_type"], Fore.WHITE))
    verified_mark = f"{Fore.GREEN}[✅ VERIFIED]{Style.RESET_ALL}" if verification["ok"] else f"{Fore.RED}[❓]{Style.RESET_ALL}"
    print(f"  {color}{label}{Style.RESET_ALL}: {Fore.CYAN}{addr}{Style.RESET_ALL}  {verified_mark}")

    print(f"\n{'─'*72}")
    print(f"{Fore.YELLOW}  ALL ADDRESSES FROM THIS PRIVATE KEY{Style.RESET_ALL}")
    print(f"{'─'*72}")
    derived = verification.get("derived", result.get("all_addresses", {}))
    for key, (label, color) in ADDRESS_LABELS.items():
        val = derived.get(key)
        if val:
            marker = f"  {Fore.GREEN}◄ TARGET MATCH{Style.RESET_ALL}" if val == addr else ""
            print(f"  {color}{label}{Style.RESET_ALL}: {val}{marker}")
    print(f"\n{'='*72}\n")

    # Save to found.txt
    sep = "="*72
    dash = "-"*72
    lines = [
        "", sep, "  🎉 MATCH FOUND",
        f"  Time        : {timestamp}",
        f"  Devices     : {devices_str}",
        f"  Range       : {range_desc}",
        f"  Crypto lib  : {CRYPTO_LIB}",
        sep, "", dash, "  VERIFICATION", dash,
        f"  Status      : {'✅ VERIFIED' if verification['ok'] else '❌ FAILED'}",
        f"  Matched type: {(verification['matched_type'] or '').upper()}",
    ]
    for note in verification["notes"]:
        lines.append(f"  {note}")
    lines += [
        "", dash, "  PRIVATE KEY", dash,
        f"  HEX         : {privkey_hex}",
        f"  WIF         : {wif}",
        f"  PubKey (C)  : {verification.get('pub_compressed', 'N/A')}",
        f"  PubKey (U)  : {verification.get('pub_uncompressed', 'N/A')}",
        "", dash, "  TARGET ADDRESS", dash,
        f"  Type        : {result['addr_type'].upper()}",
        f"  Address     : {addr}",
        "", dash, "  ALL ADDRESSES", dash,
    ]
    for key, (label, _) in ADDRESS_LABELS.items():
        val = derived.get(key)
        if val:
            marker = "  ◄◄◄ TARGET MATCH" if val == addr else ""
            lines.append(f"  {label}: {val}{marker}")
    lines += ["", sep, ""]

    with open(found_file, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"{Fore.GREEN}💾 Saved → {Fore.CYAN}{found_file}{Style.RESET_ALL}\n")

    # Telegram notification
    telegram_notify(cfg, result, verification, found_file, devices_str, range_desc)

# ------------------------------------------------------------------------------
#  Interactive device selection
# ------------------------------------------------------------------------------
def choose_devices(devices: List[Dict]) -> List[Dict]:
    """Let the user choose how many of each device type to use."""
    if not devices:
        return []

    print(f"\n{Fore.YELLOW}Available accelerators:{Style.RESET_ALL}")
    # Group by type
    by_type = {}
    for d in devices:
        by_type.setdefault(d['type'], []).append(d)

    selected = []
    for dev_type, dev_list in by_type.items():
        print(f"  {Fore.CYAN}{dev_type.upper()}: {len(dev_list)} device(s){Style.RESET_ALL}")
        for i, d in enumerate(dev_list, 1):
            print(f"    {i}. {d['name']}")
        while True:
            try:
                inp = input(f"  How many {dev_type.upper()} to use? (0-{len(dev_list)}, Enter for all): ").strip()
                if inp == "":
                    count = len(dev_list)
                else:
                    count = int(inp)
                if 0 <= count <= len(dev_list):
                    selected.extend(dev_list[:count])
                    break
                else:
                    print(f"{Fore.RED}Please enter a number between 0 and {len(dev_list)}{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Invalid input.{Style.RESET_ALL}")
    return selected

def choose_cpu_cores() -> int:
    total = multiprocessing.cpu_count()
    options = sorted(set([1, 2, 4, 8, 16, total]))
    print(f"\n{Fore.YELLOW}Select number of CPU cores:{Style.RESET_ALL}")
    for i, c in enumerate(options, 1):
        tag = f"  {Fore.CYAN}← all cores{Style.RESET_ALL}" if c == total else ""
        print(f"  {Fore.CYAN}[{i}]{Style.RESET_ALL} {c} core{tag}")
    while True:
        try:
            idx = int(input(f"\n{Fore.WHITE}Choice (1-{len(options)}): {Style.RESET_ALL}").strip()) - 1
            if 0 <= idx < len(options):
                return options[idx]
        except (ValueError, KeyboardInterrupt):
            pass
        print(f"{Fore.RED}Invalid choice.{Style.RESET_ALL}")

def setup_telegram_interactive(cfg: Dict) -> Dict:
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════╗
║  TELEGRAM BOT SETUP                             ║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
  1. Open Telegram → @BotFather → /newbot → get TOKEN
  2. Send a message to your bot
  3. Open: https://api.telegram.org/bot<TOKEN>/getUpdates
     Look for "chat":{{"id": NUMBER}} → that's your CHAT_ID
""")
    token = input(f"{Fore.WHITE}BOT TOKEN  : {Style.RESET_ALL}").strip()
    chat_id = input(f"{Fore.WHITE}CHAT ID    : {Style.RESET_ALL}").strip()
    send_file = input(f"{Fore.WHITE}Send found.txt? (y/n) [y]: {Style.RESET_ALL}").strip().lower()
    cfg["telegram"].update({
        "enabled": True,
        "bot_token": token,
        "chat_id": chat_id,
        "send_file": (send_file != "n")
    })
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=4)
    print(f"{Fore.GREEN}✅ Saved to {CONFIG_FILE}{Style.RESET_ALL}")
    return cfg

# ------------------------------------------------------------------------------
#  Banner
# ------------------------------------------------------------------------------
def print_banner(target_count: int, target_files: List[str],
                 selected_devices: List[Dict], range_desc: str):
    dev_counts = {}
    for d in selected_devices:
        t = d['type'].upper()
        dev_counts[t] = dev_counts.get(t, 0) + 1
    dev_str = " + ".join(f"{cnt}x{typ}" for typ, cnt in dev_counts.items()) if dev_counts else "CPU"

    crypto_color = Fore.GREEN if CRYPTO_LIB == "coincurve" else Fore.YELLOW
    crypto_note = "(C library, fast)" if CRYPTO_LIB == "coincurve" else "(Python, slower – install coincurve!)"

    files_str = "\n".join(f"     {Fore.CYAN}{tf}{Style.RESET_ALL}" for tf in target_files)

    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║  BITCOIN ADDRESS HUNTER  ·  MAXIMUM PERFORMANCE EDITION (FIXED)      ║
║  Multi GPU · Multi TPU · Multi CPU · Telegram · .gz Support          ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

  Detected devices : {Fore.GREEN}{dev_str}{Style.RESET_ALL}
  Private key range: {Fore.YELLOW}{range_desc}{Style.RESET_ALL}
  Crypto library   : {crypto_color}{CRYPTO_LIB}  {crypto_note}{Style.RESET_ALL}
  Address types    : P2PKH · P2WPKH · P2TR(Taproot) · P2SH · P2PKH-Uncomp

  Target files:
{files_str}
  Total targets    : {Fore.YELLOW}{target_count:,} unique addresses{Style.RESET_ALL}
""")

# ------------------------------------------------------------------------------
#  Main
# ------------------------------------------------------------------------------
def main():
    # Check for required cryptography libraries
    if not (_CCKey and BASE58_AVAILABLE) and not BIP_UTILS_AVAILABLE:
        print(f"{Fore.RED}❌ No cryptography library available!")
        print("   Install with: pip install coincurve base58 bip_utils{Style.RESET_ALL}")
        sys.exit(1)

    if CRYPTO_LIB == "bip_utils":
        print(f"{Fore.YELLOW}⚠️  coincurve not installed – performance will be suboptimal!")
        print("   Install: pip install coincurve base58{Style.RESET_ALL}")

    cfg = load_config()

    # --- Detect hardware accelerators ---
    print(f"\n{Fore.CYAN}🔍 Detecting hardware...{Style.RESET_ALL}")
    all_devices = detect_devices()
    if all_devices:
        print(f"  {Fore.GREEN}Found {len(all_devices)} accelerator device(s).{Style.RESET_ALL}")
    else:
        print(f"  {Fore.WHITE}No GPU/TPU detected, using CPU only.{Style.RESET_ALL}")

    # --- Choose which devices to use ---
    selected_devices = choose_devices(all_devices) if all_devices else []

    # Build a readable device string for display
    if selected_devices:
        dev_counts = {}
        for d in selected_devices:
            dev_counts[d['type']] = dev_counts.get(d['type'], 0) + 1
        devices_str = " + ".join(f"{cnt}x{typ.upper()}" for typ, cnt in dev_counts.items())
    else:
        devices_str = "CPU"

    # --- CPU core selection (hybrid or pure CPU) ---
    cpu_only = not selected_devices
    if cpu_only:
        num_cpu = choose_cpu_cores()
        mode_str = f"CPU×{num_cpu}"
        devices_str = f"CPU×{num_cpu}"
    else:
        print(f"{Fore.GREEN}🚀 Selected devices: {devices_str}{Style.RESET_ALL}")
        ans = input(f"{Fore.CYAN}Add CPU workers for hybrid mode? (y/n): {Style.RESET_ALL}").strip().lower()
        if ans == "y":
            num_cpu = choose_cpu_cores()
            mode_str = f"{devices_str}+CPU×{num_cpu}"
        else:
            num_cpu = 0
            mode_str = devices_str

    # --- Select private key range ---
    range_min, range_max, range_desc = select_puzzle_range()
    print(f"{Fore.GREEN}Range selected: {range_desc}{Style.RESET_ALL}")

    # --- Telegram setup ---
    tg = cfg["telegram"]
    if not tg["enabled"]:
        ans = input(f"\n{Fore.CYAN}Enable Telegram notifications? (y/n): {Style.RESET_ALL}").strip().lower()
        if ans == "y":
            cfg = setup_telegram_interactive(cfg)
    elif tg["bot_token"].startswith("YOUR_"):
        print(f"{Fore.YELLOW}⚠️  Telegram enabled but not configured.{Style.RESET_ALL}")
        ans = input(f"{Fore.CYAN}Configure now? (y/n): {Style.RESET_ALL}").strip().lower()
        if ans == "y":
            cfg = setup_telegram_interactive(cfg)

    # --- Load target addresses ---
    target_files_cfg = cfg.get("targets", ["btc.txt"])
    if len(sys.argv) > 1:
        target_files_cfg = sys.argv[1:]

    all_targets = set()
    loaded_files = []
    for tf in target_files_cfg:
        t = load_targets(tf)
        if t:
            all_targets.update(t)
            loaded_files.append(tf)

    if not all_targets:
        print(f"{Fore.RED}⚠️  No target addresses loaded!{Style.RESET_ALL}")
        sys.exit(1)

    targets = frozenset(all_targets)
    found_file = cfg.get("found_file", FOUND_FILE)

    # --- Print startup banner ---
    print_banner(len(targets), loaded_files, selected_devices, range_desc)

    # --- Test Telegram connection ---
    if tg.get("enabled") and not tg["bot_token"].startswith("YOUR_"):
        print(f"{Fore.CYAN}📡 Testing Telegram connection...{Style.RESET_ALL}")
        telegram_test(cfg, devices_str, range_desc)

    print(f"\n{Fore.WHITE}Starting search... Press Ctrl+C to stop{Style.RESET_ALL}\n")
    time.sleep(0.5)

    # --- Shared objects for workers ---
    counter = Value(ctypes.c_uint64, 0)
    found_queue = Queue()
    stop_event = multiprocessing.Event()
    procs = []
    start_time = time.time()
    gpu_batch = cfg.get("gpu_batch", 8192)
    cpu_batch = cfg.get("cpu_batch", 1000)

    def start_workers():
        workers = []
        # GPU/TPU workers for each selected device
        for dev in selected_devices:
            if dev['type'] == 'tpu':
                target = _tpu_worker
            else:
                target = _gpu_worker
            p = Process(target=target,
                        args=(dev, counter, found_queue, targets, stop_event,
                              gpu_batch, range_min, range_max))
            p.start()
            workers.append(p)
        # CPU workers
        for i in range(num_cpu):
            p = Process(target=_cpu_worker,
                        args=(i, counter, found_queue, targets, stop_event,
                              cpu_batch, range_min, range_max))
            p.start()
            workers.append(p)
        return workers

    try:
        procs = start_workers()
        # Start status display thread
        import threading
        threading.Thread(target=display_status,
                         args=(counter, start_time, mode_str, len(procs), stop_event),
                         daemon=True).start()

        # Main loop: wait for found key or KeyboardInterrupt
        while True:
            if not found_queue.empty():
                result = found_queue.get()
                stop_event.set()   # pause all workers
                save_and_display(result, cfg, found_file, devices_str, range_desc)
                # Ask whether to continue
                ans = input(f"{Fore.CYAN}Continue searching? (y/n): {Style.RESET_ALL}").strip().lower()
                if ans == "y":
                    # Terminate old workers and start fresh
                    for p in procs:
                        p.terminate()
                    procs.clear()
                    stop_event.clear()
                    counter.value = 0
                    start_time = time.time()
                    procs = start_workers()
                    threading.Thread(target=display_status,
                                     args=(counter, start_time, mode_str, len(procs), stop_event),
                                     daemon=True).start()
                else:
                    break
            time.sleep(0.1)

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⏹  Stopped by user.{Style.RESET_ALL}")
    finally:
        stop_event.set()
        for p in procs:
            p.terminate()
            p.join(timeout=2)
        elapsed = time.time() - start_time
        total = counter.value
        avg = total / elapsed if elapsed > 0 else 0
        print(f"\n{Fore.CYAN}📊 Final Statistics{Style.RESET_ALL}")
        print(f"   Devices     : {Fore.CYAN}{devices_str}{Style.RESET_ALL}")
        print(f"   Range       : {Fore.YELLOW}{range_desc}{Style.RESET_ALL}")
        print(f"   Crypto lib  : {Fore.GREEN if CRYPTO_LIB=='coincurve' else Fore.YELLOW}{CRYPTO_LIB}{Style.RESET_ALL}")
        print(f"   Total keys  : {Fore.YELLOW}{total:,}{Style.RESET_ALL}")
        print(f"   Time        : {Fore.BLUE}{elapsed:.1f}s{Style.RESET_ALL}")
        print(f"   Average     : {Fore.GREEN}{int(avg):,}/s{Style.RESET_ALL}")
        print(f"\n{Fore.WHITE}Done.{Style.RESET_ALL}")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()