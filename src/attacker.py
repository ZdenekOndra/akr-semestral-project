"""
Modul pro slovníkový a brute-force útok na hashovaná hesla.
"""

import itertools
import string
import time

from src.hashers import verify_password

# Nejčastější hesla (základ slovníku)
COMMON_PASSWORDS = [
    'password', '123456', 'qwerty', 'admin', 'letmein', 'welcome',
    'monkey', 'dragon', 'master', 'sunshine', 'princess', 'football',
    'baseball', 'shadow', '12345678', 'abc123', 'trustno1', 'iloveyou',
    'password1', 'password123', 'welcome1', 'root', 'guest', 'test',
    'love', 'angel', 'pass', '1234', '12345', '123456789', 'qwerty123',
    'superman', 'batman', 'hello', 'login', 'solo', 'access', 'flower',
    'michael', 'jessica', 'charlie', 'donald', 'thomas', 'george',
    'jordan', 'harley', 'ranger', 'daniel', 'andrew', 'andrea',
    'corvette', 'cheese', 'coffee', 'cookie', 'butter', 'hunter',
    'summer', 'winter', 'spring', 'autumn', 'secret', 'matrix',
    'abc', 'aaa', 'zzz', 'abcd', 'pass', 'test', 'user', 'demo',
]


def load_wordlist(filepath):
    """Načte slovník ze souboru (jedno heslo na řádek)."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]


def dictionary_attack(entries, wordlist):
    """
    Slovníkový útok – zkouší hesla ze slovníku.

    Args:
        entries:  List DB záznamů (username, algorithm, salt, hash).
        wordlist: List kandidátních hesel.

    Returns:
        List výsledků – každý dict: entry, found, elapsed, attempts.
    """
    results = []
    for entry in entries:
        start = time.time()
        found = None
        attempts = 0
        for word in wordlist:
            attempts += 1
            if verify_password(word, entry['hash'], entry['salt'], entry['algorithm']):
                found = word
                break
        elapsed = time.time() - start
        results.append({
            'entry': entry,
            'found': found,
            'elapsed': elapsed,
            'attempts': attempts,
        })
    return results


def brute_force_attack(entries, charset=None, max_length=4):
    """
    Útok hrubou silou – systematicky zkouší všechny kombinace.

    Args:
        entries:    List DB záznamů.
        charset:    Znakový set (default: malá písmena + číslice).
        max_length: Maximální délka testovaného hesla.

    Returns:
        List výsledků – každý dict: entry, found, elapsed, attempts.
    """
    if charset is None:
        charset = string.ascii_lowercase + string.digits

    results = []
    for entry in entries:
        start = time.time()
        found = None
        attempts = 0
        done = False
        for length in range(1, max_length + 1):
            if done:
                break
            for combo in itertools.product(charset, repeat=length):
                attempts += 1
                candidate = ''.join(combo)
                if verify_password(candidate, entry['hash'], entry['salt'], entry['algorithm']):
                    found = candidate
                    done = True
                    break
        elapsed = time.time() - start
        results.append({
            'entry': entry,
            'found': found,
            'elapsed': elapsed,
            'attempts': attempts,
        })
    return results
