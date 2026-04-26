import math
import string
import time

from src.hashers import hash_password, ALGORITHMS


def measure_hash_speed(algorithm, n=200):
    start = time.time()
    for _ in range(n):
        hash_password('testpassword123!', algorithm)
    elapsed = time.time() - start
    return {
        'algorithm': algorithm,
        'ms_per_hash': elapsed / n * 1000,
        'hashes_per_sec': n / elapsed,
    }


def password_entropy(password):
    k = 0
    if any(c in string.ascii_lowercase for c in password):
        k += 26
    if any(c in string.ascii_uppercase for c in password):
        k += 26
    if any(c in string.digits for c in password):
        k += 10
    if any(c in string.punctuation for c in password):
        k += 32
    if k == 0:
        k = 26
    return len(password) * math.log2(k)


def brute_force_charset_size(password):
    k = 0
    if any(c in string.ascii_lowercase for c in password):
        k += 26
    if any(c in string.ascii_uppercase for c in password):
        k += 26
    if any(c in string.digits for c in password):
        k += 10
    if any(c in string.punctuation for c in password):
        k += 32
    return k or 26


def format_time(seconds):
    if seconds < 1:
        return f"{seconds*1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    if seconds < 3600:
        return f"{seconds/60:.1f} min"
    if seconds < 86400:
        return f"{seconds/3600:.1f} h"
    if seconds < 86400 * 365:
        return f"{seconds/86400:.1f} dní"
    years = seconds / (86400 * 365)
    if years < 1e6:
        return f"{years:.2e} let"
    return f"{years:.2e} let"


def print_attack_summary(results, title):
    total = len(results)
    cracked = sum(1 for r in results if r['found'] is not None)
    elapsed = sum(r['elapsed'] for r in results)
    attempts = sum(r.get('attempts', 0) for r in results)

    print(f"\n  Výsledek: {cracked}/{total} prolomeno ({100*cracked/total:.0f}%)")
    print(f"  Čas celkem: {format_time(elapsed)}")
    if attempts:
        rate = attempts / elapsed if elapsed > 0 else 0
        print(f"  Pokusů: {attempts:,}  |  Rychlost: {rate:,.0f} /s")

    for r in results:
        user = r['entry'].get('username', '?')
        alg = r['entry'].get('algorithm', '?')
        if r['found']:
            print(f"    [OK] {user} ({alg}): '{r['found']}'  ({r['elapsed']:.3f}s)")
        else:
            pwd = r['entry'].get('password', '?')
            print(f"    [--] {user} ({alg}): '{pwd}' – neprolomeno")

    return {'cracked': cracked, 'total': total, 'elapsed': elapsed, 'attempts': attempts}
