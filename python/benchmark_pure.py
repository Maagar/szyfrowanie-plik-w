import os
import time
import tracemalloc
import csv
from datetime import datetime, timezone

from pure_crypto import (
    pure_aes_gcm_encrypt, pure_aes_gcm_decrypt,
    pure_chacha20_poly1305_encrypt, pure_chacha20_poly1305_decrypt,
)

RESULTS_FILE   = os.environ.get("RESULTS_FILE",   "/results/benchmark_results.csv")
TEST_FILES_DIR = os.environ.get("TEST_FILES_DIR", "/test-files")

FILE_SIZES_MB = [10]   # 1000 MB pomijamy — za wolne
RUNS = 1

# -------------------------------------------------------------------------

def run_benchmark(language, algorithm, size_mb, encrypt_fn, decrypt_fn, key):
    print(f"[{language}] {algorithm} | {size_mb} MB")

    path = os.path.join(TEST_FILES_DIR, f"test_{size_mb}mb.bin")
    with open(path, "rb") as f:
        original = f.read()

    enc_times  = []
    dec_times  = []
    ram_usages = []
    integrity  = True

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
    aes_key    = os.urandom(32)
    chacha_key = os.urandom(32)

    for size_mb in FILE_SIZES_MB:
        run_benchmark("Python-pure", "AES-256-GCM",       size_mb, pure_aes_gcm_encrypt,              pure_aes_gcm_decrypt,              aes_key)
        run_benchmark("Python-pure", "ChaCha20-Poly1305",  size_mb, pure_chacha20_poly1305_encrypt,     pure_chacha20_poly1305_decrypt,     chacha_key)

    print(f"Python-pure benchmark zakończony. Wyniki: {RESULTS_FILE}")