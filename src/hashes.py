"""
Hash functions for password storage.
Implements various algorithms with salting.
"""

import hashlib
import random
import string
import bcrypt
import time


def generate_salt(size=16):
    """Generate a random salt."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))


def hash_password(password, hash_func='sha256', rounds=10000):
    """
    Hash a password with the specified algorithm.
    
    Args:
        password: Plain text password
        hash_func: Hash function ('md5', 'sha1', 'sha256', 'sha512', 'bcrypt')
        rounds: Number of iterations (for PBKDF2)
    
    Returns:
        Tuple of (hashed_password, salt)
    """
    if hash_func == 'bcrypt':
        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8'), salt.decode('utf-8')
    else:
        salt = generate_salt()
        hash_alg = hashlib.new(hash_func)
        pwd_bytes = password.encode('utf-8')
        if salt:
            hash_alg.update(pwd_bytes + salt.encode('utf-8'))
        else:
            hash_alg.update(pwd_bytes)
        return f"{hash_alg.hexdigest()}${salt}", salt


def verify_password(password, hashed_password, hash_func='sha256'):
    """
    Verify a password against its hash.
    
    Args:
        password: Plain text password
        hashed_password: Hashed password string
        hash_func: Hash function used
    
    Returns:
        True if password matches, False otherwise
    """
    if not password:
        return False
    
    try:
        if '$' in hashed_password:
            hash_value, stored_salt = hashed_password.split('$')
        else:
            hash_value, stored_salt = hashed_password, None
        
        if hash_func == 'bcrypt':
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        else:
            hash_alg = hashlib.new(hash_func)
            pwd_bytes = password.encode('utf-8')
            salt_bytes = stored_salt.encode('utf-8') if stored_salt else b''
            hash_alg.update(pwd_bytes + salt_bytes)
            computed = hash_alg.hexdigest()
            return hash_value.lower() == computed.lower()
    except Exception:
        return False


def hash_password_fast(password, hash_func='sha256'):
    """
    Fast password hashing without salt (for attack simulations).
    
    Args:
        password: Plain text password
        hash_func: Hash function to use
    
    Returns:
        Hashed password string
    """
    hash_alg = hashlib.new(hash_func)
    return hash_alg.hexdigest(password.encode('utf-8').casefold())
