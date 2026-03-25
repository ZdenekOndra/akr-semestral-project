#!/usr/bin/env python3
"""
Password Cracker Project
Analyzes security of user passwords through various attack methods.

Author: Zdenek Ondra
Date: 2026-03-25
"""

import hashlib
import random
import string
import itertools
import time
import os
from tqdm import tqdm
from Levenshtein import distance


class PasswordHasher:
    """Utility class for hashing passwords with various algorithms."""
    
    # Supported hash functions with their parameters
    HASH_FUNCTIONS = {
        'md5': {'algorithm': 'md5', 'salt_size': 16, 'rounds': 0},
        'sha1': {'algorithm': 'sha1', 'salt_size': 16, 'rounds': 0},
        'sha256': {'algorithm': 'sha256', 'salt_size': 16, 'rounds': 0},
        'sha512': {'algorithm': 'sha512', 'salt_size': 16, 'rounds': 0},
        'bcrypt': {'algorithm': 'bcrypt', 'salt_size': 16, 'rounds': 12},
        'pbkdf2_sha256': {'algorithm': 'pbkdf2', 'hash': 'sha256', 'salt_size': 16, 'rounds': 100000},
        'pbkdf2_sha512': {'algorithm': 'pbkdf2', 'hash': 'sha512', 'salt_size': 16, 'rounds': 100000},
    }
    
    @classmethod
    def generate_salt(cls, size=16):
        """Generate a random salt."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=size))
    
    @classmethod
    def hash_password(cls, password, hash_func='sha256'):
        """Hash a password with the specified function."""
        if hash_func == 'bcrypt':
            import bcrypt
            salt = bcrypt.gensalt(rounds=12)
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed.decode('utf-8'), salt.decode('utf-8')
        elif hash_func.startswith('pbkdf2'):
            params = cls.HASH_FUNCTIONS[hash_func]
            salt = cls.generate_salt(params['salt_size'])
            hash_alg = hashlib.new(params['hash'])
            pwd_bytes = password.encode('utf-8')
            dk = hash_alg.pbkdf2(pwd_bytes, salt.encode('utf-8'), params['rounds'], dklen=32)
            return dk.hex(), salt
        else:
            params = cls.HASH_FUNCTIONS[hash_func]
            hash_alg = hashlib.new(params['algorithm'])
            pwd_bytes = password.encode('utf-8')
            salt = cls.generate_salt(params['salt_size'])
            hashed = hash_alg.hexdigest(pwd_bytes + salt.encode('utf-8'))
            return f"{hashed}${salt}", salt
    
    @classmethod
    def verify_password(cls, password, hashed_password, salt=None):
        """Verify a password against its hash."""
        if password is None:
            return False
        try:
            if '$' in hashed_password:
                hash_value, stored_salt = hashed_password.split('$')
            else:
                hash_value, stored_salt = hashed_password, None
            
            if salt is None:
                hash_func = hashed_password.split('$')[0] if '$' in hashed_password else 'sha256'
                if hash_func == 'bcrypt':
                    import bcrypt
                    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
                else:
                    params = cls.HASH_FUNCTIONS.get(hash_func, cls.HASH_FUNCTIONS['sha256'])
                    hash_alg = hashlib.new(params['algorithm'])
                    pwd_bytes = password.encode('utf-8')
                    if stored_salt:
                        salt_bytes = stored_salt.encode('utf-8')
                    else:
                        salt_bytes = params['salt_size'] * b' '
                    computed = hash_alg.hexdigest(pwd_bytes + salt_bytes)
                    return hash_value.lower() == computed.lower()
            else:
                params = cls.HASH_FUNCTIONS[hash_func]
                hash_alg = hashlib.new(params['algorithm'])
                computed = hash_alg.hexdigest(password.encode('utf-8').casefold())
                return hash_value.lower() == computed.lower()
        except Exception:
            return False
    
    @classmethod
    def load_hashes(cls, filepath):
        """Load hashed passwords from a file."""
        hashes = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    hashes.append(line)
        return hashes
    
    @classmethod
    def save_hashes(cls, hashes, filepath):
        """Save hashed passwords to a file."""
        with open(filepath, 'w', encoding='utf-8') as f:
            for hash_line in hashes:
                f.write(hash_line + '\n')


class DictionaryAttack:
    """Dictionary attack implementation."""
    
    def __init__(self, wordlist_path=None):
        """
        Initialize dictionary attack.
        
        Args:
            wordlist_path: Path to wordlist file
        """
        self.wordlist = []
        if wordlist_path:
            self._load_wordlist(wordlist_path)
        else:
            self.wordlist = self._generate_default_wordlist()
    
    def _load_wordlist(self, filepath):
        """Load wordlist from file."""
        with open(filepath, 'r', encoding='utf-8') as f:
            self.wordlist = [line.strip().lower() for line in f if line.strip()]
    
    def _generate_default_wordlist(self):
        """Generate a basic wordlist."""
        words = set()
        
        # Common words
        with open('/usr/share/dict/words', 'r') as f:
            words.update(line.strip().lower() for line in f if line.strip())
        
        # Common password words
        common_words = {
            'password', 'admin', 'root', 'guest', 'user', 'welcome', 'monkey',
            'dragon', 'master', 'sunshine', 'princess', 'football', 'baseball',
            'shadow', '123456', '12345678', 'qwerty', 'abc123', 'letmein',
            'trustno1', 'iloveyou', 'password1', 'password123', 'welcome1'
        }
        words.update(common_words)
        
        return list(words)
    
    def attack(self, hashes, hash_func='sha256', parallel=False):
        """
        Perform dictionary attack on hashed passwords.
        
        Args:
            hashes: List of hashed passwords
            hash_func: Hash function to use for cracking
            parallel: Whether to attack in parallel (not fully implemented yet)
        
        Returns:
            List of tuples (password, hash_index, hash_value)
        """
        cracked = []
        wordlist = self.wordlist[:1000] if len(self.wordlist) > 1000 else self.wordlist[:200]
        
        for i, hash_line in enumerate(hashes):
            password = None
            try:
                # Try passwords from wordlist
                for word in tqdm(wordlist, desc=f"Dictionary attack on hash {i}", leave=False, total=len(wordlist)):
                    if PasswordHasher.verify_password(word, hash_line, hash_func):
                        password = word
                        cracked.append((password, i, hash_line))
                        break
            except Exception as e:
                print(f"Error cracking hash {i}: {e}")
                pass
        
        return cracked


class BruteForceAttack:
    """Brute force attack implementation."""
    
    def __init__(self, char_set=None):
        """
        Initialize brute force attack.
        
        Args:
            char_set: Character set to use (default: lowercase, digits)
        """
        self.char_set = char_set or string.ascii_lowercase + string.digits
        self.lengths = list(range(1, 8))  # Try lengths 1-7 first, then higher
    
    def attack(self, hashes, hash_func='sha256', max_length=8):
        """
        Perform brute force attack on hashed passwords.
        
        Args:
            hashes: List of hashed passwords
            hash_func: Hash function to use
            max_length: Maximum password length to try
        
        Returns:
            List of tuples (password, hash_index, hash_value)
        """
        cracked = []
        total_combinations = sum(len(self.char_set) ** length for length in range(1, max_length + 1))
        
        for i, hash_line in enumerate(hashes):
            for length in self.lengths:
                if length > max_length:
                    break
                
                # Generate passwords of this length
                for password in itertools.product(self.char_set, repeat=length):
                    password = ''.join(password)
                    if PasswordHasher.verify_password(password, hash_line, hash_func):
                        cracked.append((password, i, hash_line))
                        break
        return cracked


class RainbowTableAttack:
    """Simplified rainbow table implementation."""
    
    def __init__(self, hash_func='sha256', reduction_count=10):
        """
        Initialize rainbow table attack.
        
        Args:
            hash_func: Hash function to use
            reduction_count: Number of reduction steps
        """
        self.hash_func = hash_func
        self.reduction_count = reduction_count
        self.table_size = 1000  # Simplified table size
        self.table = {}  # password -> reduced_hash mapping
    
    def _hash(self, password):
        """Hash a password."""
        if '$' in password:
            parts = password.split('$')
            if len(parts) == 2:
                return parts[0].lower()
        return PasswordHasher.hash_password(password, self.hash_func)[0].lower()
    
    def _reduce(self, hash_value):
        """Reduce hash to a lookup table entry."""
        return hashlib.md5(hash_value.encode('utf-8')).hexdigest()[:8]
    
    def _reverse_hash(self, reduced_hash):
        """Generate candidate passwords from reduced hash."""
        candidates = []
        for length in range(1, 6):
            for password in itertools.product(string.ascii_lowercase + string.digits, repeat=length):
                password = ''.join(password)
                if self._reduce(PasswordHasher.hash_password(password, self.hash_func)[0].lower()) == reduced_hash:
                    candidates.append(password)
        return candidates if candidates else [None]
    
    def build_table(self, wordlist_path=None):
        """
        Build rainbow table from wordlist.
        
        Args:
            wordlist_path: Path to wordlist file
        """
        if wordlist_path:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
        else:
            passwords = self._generate_wordlist()
        
        for password in passwords[:self.table_size]:
            hash_value = self._hash(password)
            reduced = self._reduce(hash_value)
            self.table[reduced] = password
    
    def _generate_wordlist(self):
        """Generate a basic wordlist."""
        words = set()
        common_words = {
            'password', 'admin', 'root', 'guest', 'user', 'welcome', 'monkey',
            'dragon', 'master', 'sunshine', 'princess', 'football', 'baseball',
            'shadow', '123456', '12345678', 'qwerty', 'abc123', 'letmein',
            'trustno1', 'iloveyou', 'password1', 'password123', 'welcome1'
        }
        for i in range(1000):
            words.add(f"password{i}")
            words.add(f"admin{i}")
            words.add(f"user{i}")
        words.update(common_words)
        return list(words)
    
    def attack(self, hashes):
        """
        Perform rainbow table attack on hashed passwords.
        
        Args:
            hashes: List of hashed passwords
        
        Returns:
            List of tuples (password, hash_index, hash_value)
        """
        cracked = []
        
        for i, hash_line in enumerate(hashes):
            try:
                if '$' in hash_line:
                    hash_value, _ = hash_line.split('$')
                else:
                    hash_value = hash_line.lower()
                
                reduced = self._reduce(hash_value)
                if reduced in self.table:
                    cracked.append((self.table[reduced], i, hash_line))
                    # Rehash to confirm
                    if PasswordHasher.verify_password(self.table[reduced], hash_line):
                        continue
                    else:
                        cracked.pop()
            except Exception:
                pass
        
        return cracked


class HashComparison:
    """Compare different hash functions."""
    
    def __init__(self, wordlist_path=None):
        """
        Initialize hash comparison.
        
        Args:
            wordlist_path: Path to wordlist for testing
        """
        self.wordlist_path = wordlist_path
        self.wordlist = self._load_wordlist() if wordlist_path else self._generate_wordlist()
    
    def _load_wordlist(self):
        """Load wordlist."""
        with open(self.wordlist_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    
    def _generate_wordlist(self):
        """Generate wordlist."""
        common_words = {
            'password', 'admin', 'root', 'guest', 'user', 'welcome', 'monkey',
            'dragon', 'master', 'sunshine', 'princess', 'football', 'baseball',
            'shadow', '123456', '12345678', 'qwerty', 'abc123', 'letmein',
            'trustno1', 'iloveyou', 'password1', 'password123', 'welcome1'
        }
        for i in range(100):
            common_words.add(f"test{i}")
        return list(common_words)
    
    def compare_hashes(self, hash_functions=None, password_count=10):
        """
        Compare hash functions by computing hash times.
        
        Args:
            hash_functions: List of hash functions to compare
            password_count: Number of passwords to test
        
        Returns:
            Dictionary with timing results
        """
        if hash_functions is None:
            hash_functions = list(PasswordHasher.HASH_FUNCTIONS.keys())
        
        results = {}
        
        for hash_func in hash_functions:
            times = []
            for _ in range(password_count):
                start = time.time()
                PasswordHasher.hash_password('test_password', hash_func)
                end = time.time()
                times.append(end - start)
            
            results[hash_func] = {
                'avg_time': sum(times) / len(times),
                'min_time': min(times),
                'max_time': max(times),
                'std_dev': (sum((t - results[hash_func]['avg_time']) ** 2 for t in times) / len(times)) ** 0.5
            }
        
        return results
    
    def compare_security(self, passwords, hash_functions=None):
        """
        Compare security of different hash functions against a wordlist.
        
        Args:
            passwords: List of passwords to test
            hash_functions: List of hash functions to compare
        
        Returns:
            Dictionary with security results
        """
        if hash_functions is None:
            hash_functions = list(PasswordHasher.HASH_FUNCTIONS.keys())
        
        results = {}
        
        for hash_func in hash_functions:
            cracked = 0
            for password in passwords:
                try:
                    if PasswordHasher.verify_password(password, password, hash_func):
                        cracked += 1
                except Exception:
                    pass
            
            results[hash_func] = {
                'passwords_cracked': cracked,
                'crack_ratio': cracked / len(passwords) if passwords else 0
            }
        
        return results


class PasswordComplexityAnalyzer:
    """Analyze password complexity and breaking time."""
    
    def __init__(self):
        """Initialize complexity analyzer."""
        self.char_sets = {
            'simple': string.ascii_lowercase,
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_lowercase,
            'numbers': string.digits,
            'alphanumeric': string.ascii_letters + string.digits,
            'common': string.ascii_lowercase + string.digits + '!@#$%^&*()-_=+',
        }
    
    def generate_passwords(self, length, char_set='common', count=1000):
        """
        Generate passwords with specified complexity.
        
        Args:
            length: Password length
            char_set: Character set to use
            count: Number of passwords to generate
        
        Returns:
            List of passwords
        """
        passwords = []
        for _ in range(count):
            password = ''.join(random.choice(char_set) for _ in range(length))
            passwords.append(password)
        return passwords
    
    def analyze_complexity(self, passwords, hash_func='sha256'):
        """
        Analyze breaking time for passwords of different complexity.
        
        Args:
            passwords: List of passwords to analyze
            hash_func: Hash function to use
        
        Returns:
            Analysis results
        """
        results = {}
        
        # Sort passwords by estimated entropy
        for password in passwords[:100]:
            entropy = 0
            unique_chars = len(set(password))
            password_length = len(password)
            
            # Simple entropy estimation
            if entropy > 0:
                entropy = unique_chars * (password_length / 2)
            
            results[password] = {
                'length': len(password),
                'unique_chars': unique_chars,
                'entropy': entropy,
                'crack_difficulty': 'easy' if entropy < 30 else 'medium' if entropy < 60 else 'hard'
            }
        
        return results


def main():
    """Main function to demonstrate password cracking capabilities."""
    
    print("=" * 60)
    print("Password Cracker Project")
    print("=" * 60)
    
    # Create sample hashed passwords for testing
    test_passwords = ['password', 'admin', 'root', 'user', 'test123', 'abc123', 'qwerty', 'monkey', 'dragon', 'master']
    hashes = []
    
    for pwd in test_passwords:
        for hash_func in ['md5', 'sha1', 'sha256', 'sha512', 'pbkdf2_sha256']:
            hashed, _ = PasswordHasher.hash_password(pwd, hash_func)
            hashes.append(hashed)
    
    print(f"\nGenerated {len(hashes)} hashed passwords")
    
    # Dictionary attack
    print("\n" + "-" * 60)
    print("Dictionary Attack")
    print("-" * 60)
    dict_attack = DictionaryAttack()
    cracked = dict_attack.attack(hashes[:20])
    print(f"Cracked {len(cracked)} passwords with dictionary attack")
    
    # Brute force attack
    print("\n" + "-" * 60)
    print("Brute Force Attack")
    print("-" * 60)
    brute_force = BruteForceAttack()
    cracked = brute_force.attack(hashes[:10])
    print(f"Cracked {len(cracked)} passwords with brute force")
    
    # Rainbow table attack
    print("\n" + "-" * 60)
    print("Rainbow Table Attack")
    print("-" * 60)
    rainbow = RainbowTableAttack()
    rainbow.build_table()
    cracked = rainbow.attack(hashes[:5])
    print(f"Cracked {len(cracked)} passwords with rainbow tables")
    
    # Hash comparison
    print("\n" + "-" * 60)
    print("Hash Function Comparison")
    print("-" * 60)
    comparison = HashComparison()
    timing = comparison.compare_hashes()
    for hash_func, times in timing.items():
        print(f"{hash_func}: avg {times['avg_time']:.4f}s")
    
    print("\n" + "=" * 60)
    print("Project completed successfully!")
    print("=" * 60)


if __name__ == '__main__':
    main()
