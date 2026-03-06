"""
SecureCrypt — Cipher Verification Script

Run this to verify every cipher works correctly:
    python verify_ciphers.py
"""

import os
import sys
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.crypto_engine import CipherFactory


def main():
    print("╔══════════════════════════════════════════════════╗")
    print("║     SecureCrypt — Cipher Verification Suite      ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    key_material = os.urandom(32)

    # ── Test 1: Basic encrypt/decrypt ────────────────────────────
    print("━━━ Test 1: Encrypt → Decrypt Round-Trip ━━━━━━━━━━")
    test_messages = [
        b"Hello, World!",
        b"",                                     # empty
        b"\x00" * 100,                            # null bytes
        b"A" * 10_000,                            # 10 KB
        os.urandom(1_000_000),                    # 1 MB random
    ]
    all_pass = True

    for name in CipherFactory.list_ciphers():
        cipher = CipherFactory.create(name, key_material)
        ok = True
        for msg in test_messages:
            try:
                encrypted = cipher.encrypt(msg)
                decrypted = cipher.decrypt(encrypted)
                if decrypted != msg:
                    ok = False
                    break
            except Exception as exc:
                print(f"  ❌ {name:<25s} ERROR: {exc}")
                ok = False
                break

        if ok:
            info = cipher.info()
            print(
                f"  ✅ {name:<25s}  "
                f"key={info['key_bits']:>3d}bit  "
                f"auth={info['auth_method']:<12s}"
            )
        else:
            print(f"  ❌ {name:<25s}  FAILED")
            all_pass = False

    print()

    # ── Test 2: Tamper detection ─────────────────────────────────
    print("━━━ Test 2: Tamper Detection ━━━━━━━━━━━━━━━━━━━━━━")
    for name in CipherFactory.list_ciphers():
        cipher = CipherFactory.create(name, key_material)
        encrypted = cipher.encrypt(b"Test tamper detection")

        # Flip a byte in the middle of ciphertext
        tampered = bytearray(encrypted)
        mid = len(tampered) // 2
        tampered[mid] ^= 0xFF
        tampered = bytes(tampered)

        try:
            cipher.decrypt(tampered)
            print(f"  ⚠️  {name:<25s}  NO tamper detection!")
            all_pass = False
        except Exception:
            print(f"  ✅ {name:<25s}  Tamper detected correctly")

    print()

    # ── Test 3: Different keys cannot decrypt ────────────────────
    print("━━━ Test 3: Wrong Key Rejection ━━━━━━━━━━━━━━━━━━━")
    key2 = os.urandom(32)
    for name in CipherFactory.list_ciphers():
        cipher1 = CipherFactory.create(name, key_material)
        cipher2 = CipherFactory.create(name, key2)
        encrypted = cipher1.encrypt(b"Secret message")

        try:
            cipher2.decrypt(encrypted)
            print(f"  ⚠️  {name:<25s}  Decrypted with wrong key!")
            all_pass = False
        except Exception:
            print(f"  ✅ {name:<25s}  Wrong key rejected")

    print()

    # ── Test 4: Benchmark ────────────────────────────────────────
    print("━━━ Test 4: Performance Benchmark (1 MB) ━━━━━━━━━━")
    data_1mb = os.urandom(1024 * 1024)
    results = []

    for name in CipherFactory.list_ciphers():
        cipher = CipherFactory.create(name, key_material)

        t0 = time.perf_counter()
        enc = cipher.encrypt(data_1mb)
        t_enc = time.perf_counter() - t0

        t0 = time.perf_counter()
        cipher.decrypt(enc)
        t_dec = time.perf_counter() - t0

        overhead = len(enc) - len(data_1mb)
        total = (t_enc + t_dec) * 1000
        enc_speed = 1.0 / t_enc if t_enc > 0 else 9999
        dec_speed = 1.0 / t_dec if t_dec > 0 else 9999

        results.append((name, total, overhead, enc_speed, dec_speed))
        print(
            f"  {name:<25s}  "
            f"enc={enc_speed:>7.1f} MB/s  "
            f"dec={dec_speed:>7.1f} MB/s  "
            f"overhead={overhead:>3d}B  "
            f"total={total:>7.1f}ms"
        )

    # Sort by speed
    results.sort(key=lambda x: x[1])
    print()
    print("━━━ Ranking ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    for rank, (name, total, overhead, _, _) in enumerate(results, 1):
        bar = "█" * max(1, int(40 * results[0][1] / (total + 0.01)))
        print(f"  {rank:>2d}. {name:<25s} {total:>7.1f}ms  {bar}")

    print()
    print("━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  Total ciphers tested: {len(CipherFactory.list_ciphers())}")
    print(f"  Recommended:          {CipherFactory.recommend()}")
    if all_pass:
        print("  Result:               🎉 ALL TESTS PASSED")
    else:
        print("  Result:               ⚠️  SOME TESTS FAILED")
    print()


if __name__ == "__main__":
    main()