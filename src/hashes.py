"""
Zpětně kompatibilní wrapper – nová implementace je v src/hashers.py.
"""
from src.hashers import (
    ALGORITHMS,
    generate_salt,
    hash_password,
    hash_unsalted as hash_password_fast,
    verify_password,
)

__all__ = [
    'ALGORITHMS', 'generate_salt', 'hash_password',
    'hash_password_fast', 'verify_password',
]
