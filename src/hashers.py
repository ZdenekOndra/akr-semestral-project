"""
Modul pro hashování hesel.
Implementuje hashování s/bez soli pro MD5, SHA-1, SHA-256, SHA-512, bcrypt, PBKDF2.
"""

import hashlib
import os
import bcrypt

# Podporované algoritmy
ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'pbkdf2_sha256']


def generate_salt(size=16):
    """Generuje náhodnou sůl jako hex řetězec."""
    return os.urandom(size).hex()


def hash_password(password, algorithm='sha256', salt=None):
    """
    Hashuje heslo s náhodnou solí.
    """
    if algorithm == 'bcrypt':
        bcrypt_salt = bcrypt.gensalt(rounds=10)
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt_salt)
        return hashed.decode('utf-8'), bcrypt_salt.decode('utf-8')

    if salt is None:
        salt = generate_salt()

    if algorithm == 'pbkdf2_sha256':
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100_000,
        )
        return dk.hex(), salt

    # md5, sha1, sha256, sha512 – hashlib
    h = hashlib.new(algorithm)
    h.update((password + salt).encode('utf-8'))
    return h.hexdigest(), salt


def hash_unsalted(password, algorithm='md5'):
    """
    Hashuje heslo BEZ soli – používá se pro demo rainbow tables.
    """
    h = hashlib.new(algorithm)
    h.update(password.encode('utf-8'))
    return h.hexdigest()


def verify_password(password, stored_hash, salt, algorithm='sha256'):
    """
    Ověří heslo vůči uloženému hashi.
    """
    if algorithm == 'bcrypt':
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception:
            return False

    computed, _ = hash_password(password, algorithm, salt)
    return computed == stored_hash
