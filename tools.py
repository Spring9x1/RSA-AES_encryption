#!/usr/bin/env python3
"""
crypto_tools.py — Simple RSA & AES command‑line utility using PyCryptodome

Features
--------
* RSA key‑pair generation (2048-bit or 3072-bit) with key length analysis.
* AES symmetric encryption (128, 192, or 256-bit GCM) for any file size.
* PURE RSA encryption / decryption (OAEP) for SMALL data payloads.
* Performance metrics (time, CPU, memory) for all crypto operations.

Dependencies
------------
pip install pycryptodome psutil

Usage examples:

# 1. Generate 2048-bit or 3072‑bit RSA keys
python tools.py rsa-generate --keysize 3072 --priv rsa_3072.pem --pub rsa_3072.pub

# 2. Encrypt RSA small file size
#    (e.g., a file with "Hello!" inside)
python tools.py rsa-encrypt --pub rsa_3072.pub --infile secret.txt --outfile secret.rsa.enc

# 3. Decrypt it back
python tools.py rsa-decrypt --priv rsa_3072.pem --infile secret.rsa.enc --outfile secret.txt

# 4. Encrypt a LARGE file with AES for comparison (changeable keysize with AES-126, 192, and 256)
python tools.py aes-encrypt --keysize 256 --infile bigfile.zip --outfile bigfile.aes.enc --keyfile aes256.key

# 5. Decrypt with the corresponding AES key
python tools.py aes-decrypt --infile bigfile.aes.enc --outfile bigfile.zip --keyfile aes256.key

Notes
-----
* RSA is now in PURE mode. It is NOT for large files. Max data size depends on the key
  (e.g., ~190 bytes for a 2048-bit key). It's intended for small data like keys or short messages.
* AES should be used for files of any significant size.
* AES ciphertext file format: [nonce][tag][ciphertext] (nonce & tag are 16 bytes each).
"""

import argparse
import os
import time
import psutil
from functools import wraps
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# ────────────────────────────────────────────────────────────────────────────────
# Performance Measurement Decorator
# ────────────────────────────────────────────────────────────────────────────────

def measure_performance(func):
    """Decorator to measure execution time, CPU, and memory usage."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        process = psutil.Process(os.getpid())
        
        # Initial measurements
        mem_before = process.memory_info().rss
        cpu_before = process.cpu_percent(interval=None)
        start_time = time.monotonic()

        # Execute the function
        result = func(*args, **kwargs)

        # Final measurements
        end_time = time.monotonic()
        cpu_after = process.cpu_percent(interval=None)
        mem_after = process.memory_info().rss
        
        # Calculate and print stats
        duration = end_time - start_time
        cpu_usage = cpu_after - cpu_before
        mem_usage = mem_after - mem_before
        
        print("\n--- Performance Stats ---")
        print(f"  [*] Waktu Proses : {duration:.4f} detik")
        print(f"  [*] Penggunaan CPU : {cpu_usage:.2f}%")
        print(f"  [*] Penggunaan Memori: {mem_usage / 1024 / 1024:.2f} MB")
        print("-------------------------\n")
        
        return result
    return wrapper

# ────────────────────────────────────────────────────────────────────────────────
# RSA helpers (Pure, for small data only)
# ────────────────────────────────────────────────────────────────────────────────

def rsa_generate(keysize: int, priv_out: str, pub_out: str) -> None:
    """Generate RSA key‑pair and save to priv_out / pub_out (PEM)."""
    print(f"[*] Generating {keysize}-bit RSA key pair... this might take a moment.")
    key = RSA.generate(keysize)
    
    private_key_data = key.export_key()
    public_key_data = key.publickey().export_key()
    
    with open(priv_out, "wb") as f:
        f.write(private_key_data)
    with open(pub_out, "wb") as f:
        f.write(public_key_data)
        
    print(f"[+] RSA keys saved → {priv_out}, {pub_out}")
    print(f"  [*] Ukuran Kunci Privat: {len(private_key_data)} bytes")
    print(f"  [*] Ukuran Kunci Publik : {len(public_key_data)} bytes")


@measure_performance
def rsa_encrypt(pub_key_path: str, infile: str, outfile: str) -> None:
    """Encrypt a SMALL file using pure RSA with OAEP padding."""
    pub_key = RSA.import_key(open(pub_key_path, "rb").read())
    
    # Calculate max data size for RSA-OAEP (SHA-256)
    key_size_bytes = pub_key.size_in_bytes()
    # Max size = key size in bytes - 2 * hash_len - 2
    max_data_len = key_size_bytes - 2 * 32 - 2

    data = open(infile, "rb").read()
    if len(data) > max_data_len:
        raise ValueError(
            f"Error: Input file is too large for pure RSA encryption.\n"
            f"Max size for this key: {max_data_len} bytes. File size: {len(data)} bytes."
        )

    cipher_rsa = PKCS1_OAEP.new(pub_key)
    ciphertext = cipher_rsa.encrypt(data)

    open(outfile, "wb").write(ciphertext)
    print(f"[+] Encrypted with Pure RSA-OAEP → {outfile}")


@measure_performance
def rsa_decrypt(priv_key_path: str, infile: str, outfile: str) -> None:
    """Decrypt a file encrypted with pure RSA-OAEP."""
    priv_key = RSA.import_key(open(priv_key_path, "rb").read())
    
    ciphertext = open(infile, "rb").read()
    
    cipher_rsa = PKCS1_OAEP.new(priv_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    
    open(outfile, "wb").write(plaintext)
    print(f"[+] Decrypted with Pure RSA-OAEP → {outfile}")


# ────────────────────────────────────────────────────────────────────────────────
# AES‑GCM helpers
# ────────────────────────────────────────────────────────────────────────────────

@measure_performance
def aes_encrypt(keyfile: str, infile: str, outfile: str, keysize: int) -> None:
    """Encrypt a file with AES-GCM using a specified key size."""
    if keyfile and os.path.exists(keyfile):
        key = open(keyfile, "rb").read()
        actual_keysize = len(key) * 8
        print(f"[*] Using existing {actual_keysize}-bit AES key from {keyfile}")
    else:
        key_bytes = keysize // 8
        key = get_random_bytes(key_bytes)
        if keyfile:
            open(keyfile, "wb").write(key)
            print(f"[+] New AES-{keysize} key saved → {keyfile} ({len(key)} bytes)")

    cipher = AES.new(key, AES.MODE_GCM)
    data = open(infile, "rb").read()
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(outfile, "wb") as f:
        for part in (cipher.nonce, tag, ciphertext):
            f.write(part)
    print(f"[+] Encrypted with AES-GCM → {outfile}")


@measure_performance
def aes_decrypt(keyfile: str, infile: str, outfile: str) -> None:
    """Decrypt a file with AES-GCM. Key size is inferred from the key file."""
    key = open(keyfile, "rb").read()
    with open(infile, "rb") as f:
        nonce, tag, ciphertext = f.read(16), f.read(16), f.read()

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    open(outfile, "wb").write(plaintext)
    print(f"[+] Decrypted with AES-GCM → {outfile}")


# ────────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="RSA & AES utility with performance metrics, powered by PyCryptodome",
        formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # RSA key gen
    g = sub.add_parser("rsa-generate", help="Generate RSA key‑pair")
    g.add_argument("--keysize", type=int, default=2048, choices=[2048, 3072], help="Key size in bits (default: 2048)")
    g.add_argument("--priv", default="private.pem", help="Private key output path")
    g.add_argument("--pub", default="public.pem", help="Public key output path")

    # RSA encrypt / decrypt
    re_help = "Encrypt a SMALL file with pure RSA-OAEP. \nWARNING: Not for large files!"
    re = sub.add_parser("rsa-encrypt", help=re_help)
    re.add_argument("--pub", required=True, help="Public key PEM")
    re.add_argument("--infile", required=True)
    re.add_argument("--outfile", required=True)

    rd = sub.add_parser("rsa-decrypt", help="Decrypt a file encrypted with pure RSA-OAEP.")
    rd.add_argument("--priv", required=True, help="Private key PEM")
    rd.add_argument("--infile", required=True)
    rd.add_argument("--outfile", required=True)

    # AES encrypt / decrypt
    ae = sub.add_parser("aes-encrypt", help="Encrypt with AES-GCM (for any file size)")
    ae.add_argument("--keysize", type=int, default=256, choices=[128, 192, 256], help="Key size in bits for a new key (default: 256)")
    ae.add_argument("--keyfile", default="aes.key", help="Key file (created if absent)")
    ae.add_argument("--infile", required=True)
    ae.add_argument("--outfile", required=True)

    ad = sub.add_parser("aes-decrypt", help="Decrypt AES-GCM ciphertext")
    ad.add_argument("--keyfile", required=True, help="Key file used for encryption")
    ad.add_argument("--infile", required=True)
    ad.add_argument("--outfile", required=True)

    args = parser.parse_args()

    try:
        match args.cmd:
            case "rsa-generate":
                rsa_generate(args.keysize, args.priv, args.pub)
            case "rsa-encrypt":
                rsa_encrypt(args.pub, args.infile, args.outfile)
            case "rsa-decrypt":
                rsa_decrypt(args.priv, args.infile, args.outfile)
            case "aes-encrypt":
                aes_encrypt(args.keyfile, args.infile, args.outfile, args.keysize)
            case "aes-decrypt":
                aes_decrypt(args.keyfile, args.infile, args.outfile)
    except ValueError as e:
        print(f"\n!!! An error occurred !!!\n{e}\n")


if __name__ == "__main__":
    main()
