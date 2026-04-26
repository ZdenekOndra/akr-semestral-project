from src.hashers import hash_password


def create_entry(username, password, algorithm='sha256'):
    hashed, salt = hash_password(password, algorithm)
    return {
        'username': username,
        'password': password,
        'algorithm': algorithm,
        'salt': salt,
        'hash': hashed,
    }


def save_database(entries, filepath):
    with open(filepath, 'w', encoding='utf-8') as f:
        for e in entries:
            f.write(f"{e['username']}:{e['algorithm']}:{e['salt']}:{e['hash']}\n")


def load_database(filepath):
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
