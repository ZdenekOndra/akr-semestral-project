import hashlib
import os
import bcrypt

ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'pbkdf2_sha256']


def generate_salt(size=16):
    return os.urandom(size).hex()


def hash_password(password, algorithm='sha256', salt=None):
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

    h = hashlib.new(algorithm)
    h.update((password + salt).encode('utf-8'))
    return h.hexdigest(), salt


def verify_password(password, stored_hash, salt, algorithm='sha256'):
    if algorithm == 'bcrypt':
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception:
            return False

    computed, _ = hash_password(password, algorithm, salt)
    return computed == stored_hash
