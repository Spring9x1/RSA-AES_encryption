#!/usr/bin/env python3
"""
crypto_tools.py — Simple RSA & AES command‑line utility using PyCryptodome

Features
--------
* RSA key‑pair generation (PEM format)
* RSA encryption / decryption with OAEP
* AES‑256‑GCM symmetric encryption / decryption

Usage examples (after `pip install pycryptodome`):

# 1. Generate 2048‑bit RSA keys
python crypto_tools.py rsa-generate --keysize 2048 --priv private.pem --pub public.pem

# 2. Encrypt a small file with the RSA public key
python crypto_tools.py rsa-encrypt --pub public.pem --infile secret.txt --outfile secret.enc

# 3. Decrypt it back
python crypto_tools.py rsa-decrypt --priv private.pem --infile secret.enc --outfile secret.txt

# 4. Encrypt ANY size file with AES‑256‑GCM (key auto‑generated & saved)
python crypto_tools.py aes-encrypt --infile bigfile.pdf --outfile bigfile.enc --keyfile aes.key

# 5. Decrypt with the saved key
python crypto_tools.py aes-decrypt --infile bigfile.enc --outfile bigfile.pdf --keyfile aes.key

Notes
-----
* RSA is best for small payloads (≤ 190 B for 2048‑bit keys). For large files use AES and, in production, protect the AES key with RSA (hybrid).
* The AES ciphertext file stores  ❰nonce❱❰tag❱❰ciphertext❱  in that order (nonce & tag are 16 bytes each).
"""

import argparse
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# ────────────────────────────────────────────────────────────────────────────────
# RSA helpers
# ────────────────────────────────────────────────────────────────────────────────

def rsa_generate(keysize: int, priv_out: str, pub_out: str) -> None:
    """Generate RSA key‑pair and save to priv_out / pub_out (PEM)."""
    key = RSA.generate(keysize)
    with open(priv_out, "wb") as f:
        f.write(key.export_key())
    with open(pub_out, "wb") as f:
        f.write(key.publickey().export_key())
    print(f"[+] RSA keys saved → {priv_out}, {pub_out}")


def rsa_encrypt(pub_key_path: str, infile: str, outfile: str) -> None:
    key = RSA.import_key(open(pub_key_path, "rb").read())
    cipher = PKCS1_OAEP.new(key)
    data = open(infile, "rb").read()
    ciphertext = cipher.encrypt(data)
    open(outfile, "wb").write(ciphertext)
    print(f"[+] Encrypted → {outfile}")


def rsa_decrypt(priv_key_path: str, infile: str, outfile: str) -> None:
    key = RSA.import_key(open(priv_key_path, "rb").read())
    cipher = PKCS1_OAEP.new(key)
    ciphertext = open(infile, "rb").read()
    plaintext = cipher.decrypt(ciphertext)
    open(outfile, "wb").write(plaintext)
    print(f"[+] Decrypted → {outfile}")


# ────────────────────────────────────────────────────────────────────────────────
# AES‑GCM helpers (AES‑256)
# ────────────────────────────────────────────────────────────────────────────────

def aes_encrypt(keyfile: str, infile: str, outfile: str) -> None:
    # Re‑use existing key if supplied, else create new 256‑bit key
    if keyfile and os.path.exists(keyfile):
        key = open(keyfile, "rb").read()
    else:
        key = get_random_bytes(32)
        if keyfile:
            open(keyfile, "wb").write(key)
            print(f"[+] AES‑256 key saved → {keyfile}")

    cipher = AES.new(key, AES.MODE_GCM)
    data = open(infile, "rb").read()
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(outfile, "wb") as f:
        # Store nonce + tag + ciphertext in single file
        for part in (cipher.nonce, tag, ciphertext):
            f.write(part)
    print(f"[+] Encrypted → {outfile}")


def aes_decrypt(keyfile: str, infile: str, outfile: str) -> None:
    key = open(keyfile, "rb").read()
    with open(infile, "rb") as f:
        nonce, tag = f.read(16), f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    open(outfile, "wb").write(plaintext)
    print(f"[+] Decrypted → {outfile}")


# ────────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="RSA & AES utility powered by PyCryptodome"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # RSA key gen
    g = sub.add_parser("rsa-generate", help="Generate RSA key‑pair")
    g.add_argument("--keysize", type=int, default=2048, help="Key size in bits (default 2048)")
    g.add_argument("--priv", default="private.pem", help="Private key output path")
    g.add_argument("--pub", default="public.pem", help="Public key output path")

    # RSA encrypt / decrypt
    re = sub.add_parser("rsa-encrypt", help="Encrypt with RSA public key")
    re.add_argument("--pub", required=True, help="Public key PEM")
    re.add_argument("--infile", required=True)
    re.add_argument("--outfile", required=True)

    rd = sub.add_parser("rsa-decrypt", help="Decrypt with RSA private key")
    rd.add_argument("--priv", required=True, help="Private key PEM")
    rd.add_argument("--infile", required=True)
    rd.add_argument("--outfile", required=True)

    # AES encrypt / decrypt
    ae = sub.add_parser("aes-encrypt", help="Encrypt with AES‑256‑GCM")
    ae.add_argument("--keyfile", default="aes.key", help="Key file (created if absent)")
    ae.add_argument("--infile", required=True)
    ae.add_argument("--outfile", required=True)

    ad = sub.add_parser("aes-decrypt", help="Decrypt AES‑256‑GCM ciphertext")
    ad.add_argument("--keyfile", default="aes.key", help="Key file")
    ad.add_argument("--infile", required=True)
    ad.add_argument("--outfile", required=True)

    args = parser.parse_args()

    match args.cmd:
        case "rsa-generate":
            rsa_generate(args.keysize, args.priv, args.pub)
        case "rsa-encrypt":
            rsa_encrypt(args.pub, args.infile, args.outfile)
        case "rsa-decrypt":
            rsa_decrypt(args.priv, args.infile, args.outfile)
        case "aes-encrypt":
            aes_encrypt(args.keyfile, args.infile, args.outfile)
        case "aes-decrypt":
            aes_decrypt(args.keyfile, args.infile, args.outfile)

if __name__ == "__main__":
    main()
