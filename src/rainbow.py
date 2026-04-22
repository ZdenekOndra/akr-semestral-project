"""
Zjednodušená implementace rainbow tables.

Princip:
- Předpočítáme řetězce: p0 -hash-> h0 -reduce(0)-> p1 -hash-> h1 -reduce(1)-> ...
- Tabulka uchovává dvojice (start, end) – klíčem je konec řetězce.
- Při útoku aplikujeme zbývající redukce na hledaný hash a hledáme konec v tabulce.
- Funguje na NESOLENÝCH hashích (sůl by znemožnila předpočítání).

Pro demo: MD5, hesla délky 3 z malé abecedy (26^3 = 17 576 hesel).
"""

import hashlib
import string
import time

CHARSET = string.ascii_lowercase          # 26 znaků
PASSWORD_LENGTH = 3                        # 26^3 = 17 576 hesel
CHAIN_LENGTH = 100                         # délka řetězce


# ---------------------------------------------------------------------------
# Interní funkce
# ---------------------------------------------------------------------------

def _hash(password):
    """MD5 hash hesla (bez soli)."""
    return hashlib.md5(password.encode('utf-8')).hexdigest()


def _reduce(hash_val, step):
    """
    Redukční funkce: mapuje hash na heslo z prohledávaného prostoru.
    Parametr step zajišťuje, že různé pozice v řetězci dávají různá hesla.
    """
    num = (int(hash_val[:8], 16) + step * 1_000_003) % (len(CHARSET) ** PASSWORD_LENGTH)
    chars = []
    for _ in range(PASSWORD_LENGTH):
        chars.append(CHARSET[num % len(CHARSET)])
        num //= len(CHARSET)
    return ''.join(chars)


def _chain_end(start, chain_length=CHAIN_LENGTH):
    """Vygeneruje konec řetězce ze startovního hesla."""
    p = start
    for i in range(chain_length):
        h = _hash(p)
        p = _reduce(h, i)
    return p


# ---------------------------------------------------------------------------
# Veřejné funkce
# ---------------------------------------------------------------------------

def build_table(num_chains=1500, chain_length=CHAIN_LENGTH):
    """
    Sestaví rainbow table.

    Args:
        num_chains:   Počet řetězců (více = vyšší pokrytí, ale více paměti/času).
        chain_length: Délka každého řetězce.

    Returns:
        Dict {end_password: start_password}.
    """
    table = {}
    # Systematicky generujeme startovní hesla z celého prostoru
    i = 0
    while len(table) < num_chains and i < len(CHARSET) ** PASSWORD_LENGTH:
        num = i
        chars = []
        for _ in range(PASSWORD_LENGTH):
            chars.append(CHARSET[num % len(CHARSET)])
            num //= len(CHARSET)
        start = ''.join(chars)
        i += 1
        end = _chain_end(start, chain_length)
        table[end] = start   # kolize jsou přijatelné – přepíšeme
    return table


def lookup(hash_val, table, chain_length=CHAIN_LENGTH):
    """
    Hledá heslo odpovídající danému hashi v rainbow table.

    Args:
        hash_val:     Hledaný MD5 hash.
        table:        Rainbow table {end: start}.
        chain_length: Délka řetězce (musí odpovídat délce při sestavení).

    Returns:
        Nalezené heslo nebo None.
    """
    for k in range(chain_length - 1, -1, -1):
        # Předpokládáme, že hash_val je na pozici k v řetězci.
        # Aplikujeme redukce od pozice k do konce.
        h = hash_val
        p = None
        for i in range(k, chain_length):
            p = _reduce(h, i)
            if i < chain_length - 1:
                h = _hash(p)
        end_candidate = p

        if end_candidate in table:
            # Znovu projdeme řetězec od začátku a ověříme nález
            start = table[end_candidate]
            p = start
            for j in range(chain_length):
                h = _hash(p)
                if h == hash_val:
                    return p   # nalezeno
                p = _reduce(h, j)
    return None


def rainbow_attack(hash_entries, table, chain_length=CHAIN_LENGTH):
    """
    Útok rainbow table na seznam nesolených MD5 hashů.

    Args:
        hash_entries: List diktů s klíčem 'hash' (nesolený MD5).
        table:        Sestavená rainbow table.
        chain_length: Délka řetězce.

    Returns:
        List výsledků – každý dict: entry, found, elapsed.
    """
    results = []
    for entry in hash_entries:
        start = time.time()
        found = lookup(entry['hash'], table, chain_length)
        elapsed = time.time() - start
        results.append({
            'entry': entry,
            'found': found,
            'elapsed': elapsed,
        })
    return results
