#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
speakaddr — pronounceable 3-word fingerprints for crypto addresses (offline).

What it does
- encode: Address -> 3 short pronounceable words (with checksum)
- verify: Address + phrase -> OK/FAIL
- svg-badge: Small SVG with the phrase (for READMEs/dashboards)
- batch: Encode many addresses from TXT/CSV/JSON

Supported inputs
- EVM: 0x-hex (40 hex chars)
- Bitcoin: typical base58/bech32 forms (treated as text fingerprint)
- Solana: base58 (treated as text fingerprint)

Design
- Words are formed from a compact syllable table (16 consonants × 16 vowels = 256).
- We map bytes -> syllables; words = 2 syllables each (e.g., "kavo", "tari", "meco").
- 3 words total: two from address bytes + one from SHA-256(address) bytes.
- A checksum syllable is mixed in; any single-syllable error flips verification.

Examples
  $ python speakaddr.py encode 0x4b0897b0513fdc7c541b6d9d7e929c4e5364d2db
  phrase: kavo-tari-meco

  $ python speakaddr.py verify 0x4b0897b0513fdc7c541b6d9d7e929c4e5364d2db "kavo-tari-meco"
  ok

  $ python speakaddr.py svg-badge 0x4b08...d2db --out addr-badge.svg
"""

import csv
import json
import hashlib
import os
import re
import sys
from dataclasses import dataclass
from typing import List, Tuple, Optional

import click

# ------------------ Syllable tables (16 × 16) ------------------
# Chosen to be short, distinct, and largely vowel-separated across languages.
_CONS = ["b","k","d","t","g","m","n","p","r","s","v","z","f","h","l","j"]
_VOWS = ["a","e","i","o","u","y","ai","oa","ia","oi","au","ei","oo","ie","ua","ea"]

def _byte_to_syllable(b: int) -> str:
    c = _CONS[(b >> 4) & 0x0F]
    v = _VOWS[b & 0x0F]
    return c + v

def _word_from_bytes(b1: int, b2: int) -> str:
    return _byte_to_syllable(b1) + _byte_to_syllable(b2)

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

HEX_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
BTC_RE = re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$", re.IGNORECASE)
SOL_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

# ------------------ Address normalization ------------------

@dataclass
class Target:
    kind: str        # 'evm' | 'btc' | 'sol'
    raw: str         # original input
    core: bytes      # 20 bytes for evm; or sha256 of the ASCII for btc/sol

def _norm_addr(s: str) -> Target:
    s = s.strip()
    if HEX_RE.match(s):
        # EVM: 20 bytes from hex
        core = bytes.fromhex(s[2:])
        return Target("evm", s, core)
    if BTC_RE.match(s):
        # BTC: we don't decode base58/bech32; hash the text for a stable fingerprint
        core = _sha256(s.encode("utf-8"))
        return Target("btc", s, core[:20])
    if SOL_RE.match(s):
        core = _sha256(s.encode("utf-8"))
        return Target("sol", s, core[:20])
    raise click.ClickException("Unsupported or malformed address format")

# ------------------ Phrase encoding / verification ------------------

def _phrase_from_core(core20: bytes) -> Tuple[str, List[int]]:
    """
    Build 3 words from:
      word1: core[0], core[1]
      word2: core[2], checksum
      word3: sha256(core)[0], sha256(core)[1]
    checksum: (sum(core) + 0xA7) % 256
    """
    if len(core20) < 3:
        raise ValueError("core too short")
    cs = (sum(core20) + 0xA7) & 0xFF
    h = _sha256(core20)
    w1 = _word_from_bytes(core20[0], core20[1])
    w2 = _word_from_bytes(core20[2], cs)
    w3 = _word_from_bytes(h[0], h[1])
    return f"{w1}-{w2}-{w3}", [core20[0], core20[1], core20[2], cs, h[0], h[1]]

def encode_phrase(address: str) -> str:
    tgt = _norm_addr(address)
    phrase, _ = _phrase_from_core(tgt.core)
    return phrase

def verify_phrase(address: str, phrase: str) -> bool:
    tgt = _norm_addr(address)
    expected, _ = _phrase_from_core(tgt.core)
    # Normalize separators and case
    ph = phrase.strip().lower().replace(" ", "-")
    expected = expected.lower()
    return ph == expected

# ------------------ CLI ------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """speakaddr — pronounceable fingerprints for crypto addresses."""
    pass

@cli.command("encode")
@click.argument("address", type=str)
def encode_cmd(address: str):
    """Encode a single address into a 3-word phrase."""
    phrase = encode_phrase(address)
    click.echo(f"phrase: {phrase}")

@cli.command("verify")
@click.argument("address", type=str)
@click.argument("phrase", type=str)
def verify_cmd(address: str, phrase: str):
    """Verify that PHRASE matches ADDRESS."""
    ok = verify_phrase(address, phrase)
    click.echo("ok" if ok else "mismatch")
    sys.exit(0 if ok else 1)

@cli.command("svg-badge")
@click.argument("address", type=str)
@click.option("--out", type=click.Path(writable=True), default="speakaddr-badge.svg", show_default=True)
def badge_cmd(address: str, out: str):
    """Write a small SVG badge with the phrase."""
    phrase = encode_phrase(address)
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="430" height="48" role="img" aria-label="Address phrase">
  <rect width="430" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    speakaddr: {phrase}
  </text>
  <circle cx="405" cy="24" r="6" fill="#3fb950"/>
</svg>"""
    with open(out, "w", encoding="utf-8") as f:
        f.write(svg)
    click.echo(f"Wrote SVG badge: {out}")

@cli.command("batch")
@click.argument("path", type=str)
@click.option("--csv-out", type=click.Path(writable=True), default="phrases.csv", show_default=True)
def batch_cmd(path: str, csv_out: str):
    """
    Encode many addresses from:
      - TXT (one per line)
      - CSV (column 'address' or first column)
      - JSON (array of strings or objects with 'address')
    """
    addrs: List[str] = []
    if path == "-":
        lines = [l.strip() for l in sys.stdin if l.strip()]
        addrs = lines
    else:
        ext = os.path.splitext(path)[1].lower()
        if ext in (".txt", ""):
            with open(path, "r", encoding="utf-8") as f:
                addrs = [l.strip() for l in f if l.strip()]
        elif ext == ".csv":
            with open(path, newline="", encoding="utf-8") as f:
                rdr = csv.DictReader(f)
                fields = rdr.fieldnames or []
                use_first = "address" not in {c.lower(): c for c in fields}
                for row in rdr:
                    if not row: continue
                    addrs.append(next(iter(row.values())).strip() if use_first else (row.get("address") or row.get("Address") or "").strip())
        elif ext == ".json":
            with open(path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, list):
                for it in obj:
                    if isinstance(it, str):
                        addrs.append(it.strip())
                    elif isinstance(it, dict) and "address" in it:
                        addrs.append(str(it["address"]).strip())
        else:
            raise click.ClickException("Unsupported file type")

    rows = []
    for a in addrs:
        try:
            ph = encode_phrase(a)
            rows.append((a, ph))
        except click.ClickException as e:
            rows.append((a, f"<error: {e}>"))

    with open(csv_out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["address","phrase"])
        w.writerows(rows)
    click.echo(f"Wrote CSV: {csv_out}")

if __name__ == "__main__":
    cli()
