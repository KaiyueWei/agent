#!/usr/bin/env python3
"""
decrypt_flag2.py

Usage:
  python3 decrypt_flag2.py --priv priv.pem --service1 service1.raw --service2 service2.raw --out plaintext.bin

What it does:
  1. Normalizes service1/raw and service2/raw (detects and decodes base64 or hex, or treats as binary).
  2. RSA-OAEP(SHA256) decrypt service1.bin using priv.pem to recover key_string.
  3. Derive AES-256 key = SHA256(key_string) (key_string treated as ASCII text).
  4. service2.bin expected format: IV(16 bytes) || ciphertext. Decrypt AES-CBC and PKCS7-unpad.
  5. Save plaintext to --out (default plaintext.bin) and print the text to stdout.

Notes:
  - Make sure priv.pem is an RSA private key in PEM format.
  - The script strips trailing newlines from the recovered key_string before hashing.
"""

import argparse
import base64
import binascii
import hashlib
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding as sympadding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HEX_CHAR_RE = re.compile(rb'^[0-9a-fA-F\s]+$')


def try_base64_decode(data: bytes):
    """Try base64 decode; return bytes or raise."""
    try:
        return base64.b64decode(data, validate=True)
    except binascii.Error:
        cleaned = re.sub(rb'\s+', b'', data)
        try:
            return base64.b64decode(cleaned, validate=True)
        except Exception:
            # Fall back to permissive decode (accepts misplaced padding) before giving up.
            return base64.b64decode(cleaned, validate=False)


def try_hex_decode(data: bytes):
    """Try hex decode by stripping non-hex and converting; return bytes or raise."""
    # Keep only hex chars 0-9a-fA-F
    s = re.sub(rb'[^0-9a-fA-F]', b'', data)
    if len(s) == 0:
        raise ValueError("no hex chars")
    # If odd length, fail
    if len(s) % 2 != 0:
        # Maybe hex was ascii hex but with newline etc. Try stripping whitespace only:
        s2 = re.sub(rb'\s+', b'', data)
        if len(s2) % 2 != 0:
            raise ValueError("odd-length hex")
        s = s2
    return bytes.fromhex(s.decode())


def normalize_input_file(path: Path, out_bin: Path):
    """Read path, attempt base64 -> hex -> raw, write normalized bytes to out_bin."""
    raw = path.read_bytes()
    # Treat inputs that only contain hex digits/whitespace as hex before attempting base64.
    if HEX_CHAR_RE.fullmatch(raw):
        try:
            dec = try_hex_decode(raw)
            out_bin.write_bytes(dec)
            return
        except Exception:
            pass
    # Try base64
    try:
        dec = try_base64_decode(raw)
        out_bin.write_bytes(dec)
        return
    except Exception:
        pass
    # Try hex
    try:
        dec = try_hex_decode(raw)
        out_bin.write_bytes(dec)
        return
    except Exception:
        pass
    # Assume binary as-is
    out_bin.write_bytes(raw)


def rsa_decrypt_rsa_oaep_sha256(priv_pem_path: Path, ciphertext_path: Path) -> bytes:
    priv_pem = priv_pem_path.read_bytes()
    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    ct = ciphertext_path.read_bytes()
    key_bytes = private_key.key_size // 8

    # Some challenge dumps repeat the same RSA block multiple times; trim if so.
    if len(ct) != key_bytes and len(ct) % key_bytes == 0:
        chunk = ct[:key_bytes]
        if chunk * (len(ct) // key_bytes) == ct:
            print(f"[!] Detected repeated RSA block ({len(ct)} bytes == {len(ct)//key_bytes} copies). Using first block only.")
            ct = chunk

    if len(ct) != key_bytes:
        raise ValueError(f"RSA ciphertext length {len(ct)} bytes does not match key size {key_bytes}.")

    pt = private_key.decrypt(
        ct,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return pt


def derive_aes_key_from_string(key_string: str) -> bytes:
    """
    Compute SHA-256 over the supplied key string.

    Some challenge dumps prepend labels such as 'KEY: ' before the secret.
    In that case we strip everything up to (and including) the first colon
    before hashing so the derived key matches the intended value.
    """
    payload = key_string
    if ":" in key_string:
        label, remainder = key_string.split(":", 1)
        if label.strip().upper() == "KEY":
            payload = remainder.strip()
    return hashlib.sha256(payload.encode()).digest()


def aes_cbc_decrypt_and_unpad(aes_key: bytes, data: bytes) -> bytes:
    if len(data) < 16:
        raise ValueError("ciphertext too short to contain IV + cipher")
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    # Unpad PKCS7 (block size 128 bits)
    unpadder = sympadding.PKCS7(128).unpadder()
    pt = unpadder.update(padded) + unpadder.finalize()
    return pt


def main():
    parser = argparse.ArgumentParser(description="Decrypt Flag2: RSA -> AES flow.")
    parser.add_argument("--priv", required=True, type=Path, help="RSA private key (PEM)")
    parser.add_argument("--service1", required=True, type=Path, help="service1 raw file (RSA ciphertext; raw/hex/base64 allowed)")
    parser.add_argument("--service2", required=True, type=Path, help="service2 raw file (IV||cipher; raw/hex/base64 allowed)")
    parser.add_argument("--out", type=Path, default=Path("plaintext.bin"), help="where to write plaintext output")
    parser.add_argument("--tmpdir", type=Path, default=Path("."), help="temp dir for normalized binaries")
    args = parser.parse_args()

    tmp = args.tmpdir
    s1_bin = tmp / "service1.bin"
    s2_bin = tmp / "service2.bin"

    print("[*] Normalizing inputs (detecting base64/hex/binary)...")
    normalize_input_file(args.service1, s1_bin)
    normalize_input_file(args.service2, s2_bin)
    print(f"    wrote normalized: {s1_bin} ({s1_bin.stat().st_size} bytes), {s2_bin} ({s2_bin.stat().st_size} bytes)")

    # RSA decrypt
    print("[*] RSA decrypting service1 -> recovering key string (OAEP SHA-256)...")
    try:
        pt = rsa_decrypt_rsa_oaep_sha256(args.priv, s1_bin)
    except Exception as e:
        print("ERROR: RSA decryption failed:", e)
        sys.exit(2)

    # Interpret key string: decode as UTF-8 and strip whitespace/newlines
    try:
        key_string = pt.decode(errors="strict").strip()
    except Exception:
        # fallback: display hex if it's not valid UTF-8
        key_string = pt.hex()
        print("Warning: RSA plaintext isn't valid UTF-8, using hex():", key_string)

    print("[+] Recovered key_string (strip):", repr(key_string))

    # Derive AES key
    aes_key = derive_aes_key_from_string(key_string)
    print("[*] Derived AES-256 key (SHA256 of key_string).")

    # Prepare service 2 bytes
    s2_bytes = s2_bin.read_bytes()
    # If the normalized service2 looks like a zip (starts with PK), report and quit — no AES necessary.
    if s2_bytes.startswith(b"PK\x03\x04"):
        print("[!] service2 appears to be a raw ZIP file (starts with PK). Saving as is.")
        args.out.write_bytes(s2_bytes)
        print(f"[+] Wrote {args.out} (raw zip). Inspect with: unzip -l {args.out}")
        return

    print("[*] Decrypting AES-CBC (IV = first 16 bytes) ...")
    try:
        plaintext = aes_cbc_decrypt_and_unpad(aes_key, s2_bytes)
    except Exception as e:
        print("ERROR: AES decryption/unpadding failed:", e)
        sys.exit(3)

    args.out.write_bytes(plaintext)
    print(f"[+] Wrote plaintext to {args.out} ({len(plaintext)} bytes).")
    # Also print small preview
    try:
        txt = plaintext.decode(errors="replace")
        print("----- BEGIN PLAINTEXT PREVIEW -----")
        print(txt)
        print("-----  END PLAINTEXT PREVIEW  -----")
    except Exception:
        print("plaintext written (binary).")

if __name__ == "__main__":
    main()
