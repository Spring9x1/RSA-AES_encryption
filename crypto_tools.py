#!/usr/bin/env python3
"""
crypto_tools.py — Simple RSA & AES command‑line utility using PyCryptodome

Features
--------
* RSA key‑pair generation (PEM format) with key length analysis.
* RSA hybrid encryption / decryption for LARGE files (AES-256-GCM + RSA-OAEP).
* AES‑256‑GCM symmetric encryption / decryption for any file size.
* Performance metrics (time, CPU, memory) for all crypto operations.

Dependencies
------------
pip install pycryptodome psutil

Usage examples:

# 1. Generate 2048‑bit RSA keys
python crypto_tools.py rsa-generate --keysize 2048 --priv private.pem --pub public.pem

# 2. Encrypt a LARGE file with the RSA public key (Hybrid Encryption)
python crypto_tools.py rsa-encrypt --pub public.pem --infile bigfile.zip --outfile bigfile.rsa.enc

# 3. Decrypt it back
python crypto_tools.py rsa-decrypt --priv private.pem --infile bigfile.rsa.enc --outfile bigfile.zip

# 4. Encrypt the same LARGE file with AES‑256‑GCM for comparison
python crypto_tools.py aes-encrypt --infile bigfile.zip --outfile bigfile.aes.enc --keyfile aes.key

# 5. Decrypt with the saved AES key
python crypto_tools.py aes-decrypt --infile bigfile.aes.enc --outfile bigfile.zip --keyfile aes.key

Notes
-----
* RSA encryption is now a hybrid scheme: a random AES key encrypts the data, and the RSA key encrypts that AES key.
* RSA encrypted file format: [encrypted AES key][nonce][tag][AES ciphertext]
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
# RSA helpers (with Hybrid Encryption for large files)
# ────────────────────────────────────────────────────────────────────────────────

def rsa_generate(keysize: int, priv_out: str, pub_out: str) -> None:
    """Generate RSA key‑pair and save to priv_out / pub_out (PEM)."""
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
    """Encrypt a large file using RSA hybrid encryption (RSA-OAEP + AES-GCM)."""
    # 1. Generate a random one-time AES session key
    session_key = get_random_bytes(32)  # AES-256

    # 2. Encrypt the session key with the RSA public key
    pub_key = RSA.import_key(open(pub_key_path, "rb").read())
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    # 3. Encrypt the actual data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    data = open(infile, "rb").read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    # 4. Save everything to the output file
    with open(outfile, "wb") as f:
        # Format: [encrypted session key][nonce][tag][ciphertext]
        f.write(encrypted_session_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)
    print(f"[+] Encrypted with RSA Hybrid → {outfile}")


@measure_performance
def rsa_decrypt(priv_key_path: str, infile: str, outfile: str) -> None:
    """Decrypt a large file encrypted with RSA hybrid encryption."""
    priv_key = RSA.import_key(open(priv_key_path, "rb").read())
    
    with open(infile, "rb") as f:
        # 1. Read all parts from the file based on key size and AES-GCM standard sizes
        key_size_bytes = priv_key.size_in_bytes()
        encrypted_session_key = f.read(key_size_bytes)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    # 2. Decrypt the session key with the RSA private key
    cipher_rsa = PKCS1_OAEP.new(priv_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    # 3. Decrypt the actual data with the recovered AES session key
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    open(outfile, "wb").write(plaintext)
    print(f"[+] Decrypted with RSA Hybrid → {outfile}")


# ────────────────────────────────────────────────────────────────────────────────
# AES‑GCM helpers (AES‑256)
# ────────────────────────────────────────────────────────────────────────────────

@measure_performance
def aes_encrypt(keyfile: str, infile: str, outfile: str) -> None:
    """Encrypt a file with AES-256-GCM."""
    if keyfile and os.path.exists(keyfile):
        key = open(keyfile, "rb").read()
    else:
        key = get_random_bytes(32)
        if keyfile:
            open(keyfile, "wb").write(key)
            print(f"[+] AES‑256 key saved → {keyfile} ({len(key)} bytes)")

    cipher = AES.new(key, AES.MODE_GCM)
    data = open(infile, "rb").read()
    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(outfile, "wb") as f:
        # Store nonce + tag + ciphertext in single file
        for part in (cipher.nonce, tag, ciphertext):
            f.write(part)
    print(f"[+] Encrypted with AES-GCM → {outfile}")


@measure_performance
def aes_decrypt(keyfile: str, infile: str, outfile: str) -> None:
    """Decrypt a file with AES-256-GCM."""
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
        formatter_class=argparse.RawTextHelpFormatter # To show newlines in help
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # RSA key gen
    g = sub.add_parser("rsa-generate", help="Generate RSA key‑pair")
    g.add_argument("--keysize", type=int, default=2048, help="Key size in bits (default 2048)")
    g.add_argument("--priv", default="private.pem", help="Private key output path")
    g.add_argument("--pub", default="public.pem", help="Public key output path")

    # RSA encrypt / decrypt
    re_help = "Encrypt a large file with RSA hybrid encryption.\n(Generates a temp AES key, encrypts data with it, then encrypts the AES key with RSA)."
    re = sub.add_parser("rsa-encrypt", help=re_help)
    re.add_argument("--pub", required=True, help="Public key PEM")
    re.add_argument("--infile", required=True)
    re.add_argument("--outfile", required=True)

    rd_help = "Decrypt a file encrypted with the RSA hybrid scheme."
    rd = sub.add_parser("rsa-decrypt", help=rd_help)
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
