"""
Modul pro správu databáze hashovaných hesel.
Formát záznamu: username:algorithm:salt:hash
"""

from src.hashers import hash_password


def create_entry(username, password, algorithm='sha256'):
    """
    Vytvoří záznam databáze pro dané heslo.
    """
    hashed, salt = hash_password(password, algorithm)
    return {
        'username': username,
        'password': password,
        'algorithm': algorithm,
        'salt': salt,
        'hash': hashed,
    }


def save_database(entries, filepath):
    """Uloží záznamy do souboru."""
    with open(filepath, 'w', encoding='utf-8') as f:
        for e in entries:
            f.write(f"{e['username']}:{e['algorithm']}:{e['salt']}:{e['hash']}\n")


def load_database(filepath):
    """
    Načte záznamy ze souboru.

    """
    entries = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(':', 3)
            if len(parts) == 4:
                entries.append({
                    'username': parts[0],
                    'algorithm': parts[1],
                    'salt': parts[2],
                    'hash': parts[3],
                })
    return entries
