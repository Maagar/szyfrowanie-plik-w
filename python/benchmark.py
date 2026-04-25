import os
import time
import tracemalloc
import csv
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

RESULTS_FILE   = os.environ.get("RESULTS_FILE",   "/results/benchmark_results.csv")
TEST_FILES_DIR = os.environ.get("TEST_FILES_DIR", "/test-files")

FILE_SIZES_MB = [10, 100, 1000]
RUNS = 3

# -------------------------------------------------------------------------

def aes_encrypt(key, plaintext):
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct

def aes_decrypt(key, blob):
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)

def chacha_encrypt(key, plaintext):
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return nonce + ct

def chacha_decrypt(key, blob):
    return ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], None)

# -------------------------------------------------------------------------

def triple_des_encrypt(key, plaintext):
    iv = os.urandom(8)
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ct

def triple_des_decrypt(key, blob):
    iv = blob[:8]
    ct = blob[8:]
    
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    
    unpadder = padding.PKCS7(64).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# -------------------------------------------------------------------------

def run_benchmark(language, algorithm, size_mb, encrypt_fn, decrypt_fn, key):
    print(f"[{language}] {algorithm} | {size_mb} MB")

    path = os.path.join(TEST_FILES_DIR, f"test_{size_mb}mb.bin")
    with open(path, "rb") as f:
        original = f.read()

    enc_times = []
    dec_times = []
    ram_usages = []
    integrity = True

    for _ in range(RUNS):
        tracemalloc.start()

        t0 = time.perf_counter()
        encrypted = encrypt_fn(key, original)
        enc_times.append((time.perf_counter() - t0) * 1000)

        t1 = time.perf_counter()
        decrypted = decrypt_fn(key, encrypted)
        dec_times.append((time.perf_counter() - t1) * 1000)

        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        ram_usages.append(peak / (1024 * 1024))

        if decrypted != original:
            integrity = False

    enc_med = sorted(enc_times)[RUNS // 2]
    dec_med = sorted(dec_times)[RUNS // 2]
    ram_med = sorted(ram_usages)[RUNS // 2]

    append_csv(language, algorithm, size_mb, enc_med, dec_med, ram_med, integrity)
    print(f"  encrypt={enc_med:.0f} ms  decrypt={dec_med:.0f} ms  ram={ram_med:.0f} MB  ok={integrity}")

def append_csv(lang, algo, size_mb, enc_ms, dec_ms, ram_mb, integrity):
    with open(RESULTS_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            lang, algo, size_mb,
            f"{enc_ms:.0f}", f"{dec_ms:.0f}", f"{ram_mb:.0f}",
            str(integrity).lower(),
            datetime.now(timezone.utc).isoformat()
        ])

# -------------------------------------------------------------------------

if __name__ == "__main__":
    for size_mb in FILE_SIZES_MB:
        run_benchmark("Python",      "AES-256-GCM",      size_mb, aes_encrypt,   aes_decrypt,   AESGCM.generate_key(bit_length=256))
        run_benchmark("Python",      "ChaCha20-Poly1305", size_mb, chacha_encrypt, chacha_decrypt, ChaCha20Poly1305.generate_key())
        run_benchmark("Python",      "TripleDES",        size_mb, triple_des_encrypt, triple_des_decrypt, os.urandom(24))

    print(f"{RESULTS_FILE}")