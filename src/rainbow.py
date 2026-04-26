import hashlib
import string
import time

CHARSET = string.ascii_lowercase
PASSWORD_LENGTH = 3
CHAIN_LENGTH = 100


def _hash(password):
    return hashlib.md5(password.encode('utf-8')).hexdigest()


def _reduce(hash_val, step):
    num = (int(hash_val[:8], 16) + step * 1_000_003) % (len(CHARSET) ** PASSWORD_LENGTH)
    chars = []
    for _ in range(PASSWORD_LENGTH):
        chars.append(CHARSET[num % len(CHARSET)])
        num //= len(CHARSET)
    return ''.join(chars)


def _chain_end(start, chain_length=CHAIN_LENGTH):
    p = start
    for i in range(chain_length):
        h = _hash(p)
        p = _reduce(h, i)
    return p


def build_table(num_chains=1500, chain_length=CHAIN_LENGTH):
    table = {}
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
        table[end] = start
    return table


def lookup(hash_val, table, chain_length=CHAIN_LENGTH):
    for k in range(chain_length - 1, -1, -1):
        h = hash_val
        p = None
        for i in range(k, chain_length):
            p = _reduce(h, i)
            if i < chain_length - 1:
                h = _hash(p)
        end_candidate = p

        if end_candidate in table:
            start = table[end_candidate]
            p = start
            for j in range(chain_length):
                h = _hash(p)
                if h == hash_val:
                    return p
                p = _reduce(h, j)
    return None


def rainbow_attack(hash_entries, table, chain_length=CHAIN_LENGTH):
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
