#!/usr/bin/env python3
"""
Password Analysis Module
Analyzes password security, hash functions, and attack effectiveness.
"""

import hashlib
import time
import random
import string
import statistics
from collections import defaultdict
from password_cracker import (
    PasswordHasher, DictionaryAttack, BruteForceAttack,
    RainbowTableAttack, HashComparison, PasswordComplexityAnalyzer
)


class SecurityAnalyzer:
    """Main security analysis class."""
    
    def __init__(self, wordlist_path=None):
        """
        Initialize security analyzer.
        
        Args:
            wordlist_path: Path to wordlist file for testing
        """
        self.wordlist = []
        if wordlist_path:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                self.wordlist = [line.strip() for line in f if line.strip()]
        else:
            self.wordlist = self._generate_wordlist()
        
        self.results = {}
    
    def _generate_wordlist(self):
        """Generate default wordlist."""
        words = set()
        common = {
            'password', 'admin', 'root', 'guest', 'user', 'welcome', 'monkey',
            'dragon', 'master', 'sunshine', 'princess', 'football', 'baseball',
            'shadow', '123456', '12345678', 'qwerty', 'abc123', 'letmein',
            'trustno1', 'iloveyou', 'password1', 'password123', 'welcome1',
            'love', 'star', 'honey', 'sweet', 'baby', 'angel', 'flower',
            'superman', 'batman', 'spiderman', 'flash', 'joker', 'robin',
            'test1', 'test2', 'test3', 'pass1', 'pass2', 'pass3'
        }
        words.update(common)
        
        # Add common patterns
        for i in range(100):
            words.add(f"user{i}")
            words.add(f"admin{i}")
            words.add(f"test{i}")
            words.add(f"pass{i}")
            words.add(f"love{i}")
        
        # Common substitutions
        for base in ['password', 'admin', 'root', 'user', 'master']:
            for suffix in ['', '1', '2', '3', '!', '@', '#', '$', '%', '^']:
                words.add(f"{base}{suffix}")
        
        return list(words)
    
    def hash_function_analysis(self, hash_functions=None):
        """
        Analyze different hash functions for security and performance.
        
        Args:
            hash_functions: List of hash functions to analyze
        
        Returns:
            Analysis results
        """
        if hash_functions is None:
            hash_functions = ['md5', 'sha1', 'sha256', 'sha512', 
                           'bcrypt', 'pbkdf2_sha256', 'pbkdf2_sha512']
        
        print("\n" + "=" * 70)
        print("HASH FUNCTION SECURITY ANALYSIS")
        print("=" * 70)
        
        results = {}
        
        for hash_func in hash_functions:
            print(f"\nTesting {hash_func}...")
            
            # Generate test passwords
            test_passwords = [
                'password', 'admin123', 'qwerty', 'letmein', 'welcome',
                '123456', 'abc123', 'monkey', 'dragon', 'master',
                'testpassword', 'simplerandom', 'complexpassword2026!'
            ]
            
            # Time hash computation
            times = []
            for _ in range(100):
                start = time.time()
                PasswordHasher.hash_password('test', hash_func)
                end = time.time()
                times.append(end - start)
            
            avg_time = sum(times) / len(times) * 1000  # Convert to ms
            
            # Analyze salt usage
            has_salt = hash_func in ['bcrypt', 'pbkdf2_sha256', 'pbkdf2_sha512']
            salt_size = 16 if has_salt else 0
            
            # Security assessment
            security_level = self._assess_security(hash_func, avg_time, has_salt, salt_size)
            
            results[hash_func] = {
                'hash_function': hash_func,
                'average_time_ms': avg_time,
                'has_salt': has_salt,
                'salt_size': salt_size,
                'security_level': security_level,
                'recommendation': self._get_recommendation(hash_func)
            }
            
            print(f"  Avg time: {avg_time:.2f}ms")
            print(f"  Salt used: {has_salt} ({salt_size} bytes)")
            print(f"  Security: {security_level}")
        
        return results
    
    def _assess_security(self, hash_func, avg_time, has_salt, salt_size):
        """Assess security level of a hash function."""
        score = 0
        
        if has_salt:
            score += 30
        
        if salt_size >= 16:
            score += 20
        
        if hash_func in ['bcrypt', 'argon2']:
            score += 50
        elif hash_func == 'pbkdf2_sha512':
            score += 35
        elif hash_func == 'pbkdf2_sha256':
            score += 30
        elif hash_func == 'sha256':
            score += 15
        elif hash_func == 'sha512':
            score += 20
        elif hash_func in ['md5', 'sha1']:
            score += 5
        
        if score >= 80:
            return 'EXCELLENT'
        elif score >= 50:
            return 'GOOD'
        elif score >= 25:
            return 'POOR'
        else:
            return 'CRITICAL'
    
    def _get_recommendation(self, hash_func):
        """Get security recommendation for a hash function."""
        if hash_func in ['bcrypt', 'argon2']:
            return 'HIGHLY RECOMMENDED - Industry standard for password hashing'
        elif hash_func == 'sha256':
            return 'RECOMMENDED FOR BASIC USE - Use with proper salting'
        elif hash_func in ['sha1', 'sha512']:
            return 'AVOID FOR PASSWORDS - Use stronger alternatives'
        elif hash_func in ['md5', 'sha1']:
            return 'NOT RECOMMENDED - Cryptographically broken for passwords'
        else:
            return 'USE WITH CAUTION'
    
    def attack_effectiveness_comparison(self, hash_functions=None, test_passwords=None):
        """
        Compare effectiveness of different attacks.
        
        Args:
            hash_functions: List of hash functions to test
            test_passwords: List of test passwords
        
        Returns:
            Comparison results
        """
        if hash_functions is None:
            hash_functions = ['md5', 'sha1', 'sha256', 'sha512', 'pbkdf2_sha256']
        
        if test_passwords is None:
            test_passwords = ['password', 'admin', 'test123', 'qwerty']
        
        print("\n" + "=" * 70)
        print("ATTACK EFFECTIVENESS COMPARISON")
        print("=" * 70)
        
        results = {}
        
        for hash_func in hash_functions:
            print(f"\n\nHash Function: {hash_func}")
            print("-" * 50)
            
            # Create hashed passwords
            hashed_passwords = []
            for pwd in test_passwords:
                hashed, salt = PasswordHasher.hash_password(pwd, hash_func)
                hashed_passwords.append((pwd, hashed))
            
            # Dictionary attack
            print(f"  Dictionary attack...")
            dict_attack = DictionaryAttack()
            dict_cracked = []
            for original, hashed in hashed_passwords:
                cracked = dict_attack.attack([hashed])
                if cracked:
                    dict_cracked.append(original)
            
            dict_success_rate = len(dict_cracked) / len(test_passwords) * 100
            
            # Brute force attack
            print(f"  Brute force attack...")
            brute_force = BruteForceAttack()
            brute_cracked = []
            for original, hashed in hashed_passwords:
                cracked = brute_force.attack([hashed], max_length=5)
                if cracked:
                    brute_cracked.append(original)
            
            brute_success_rate = len(brute_cracked) / len(test_passwords) * 100
            
            # Store results
            results[hash_func] = {
                'hash_function': hash_func,
                'dictionary_attack_success': dict_success_rate,
                'brute_force_success': brute_success_rate,
                'passwords_tested': len(test_passwords)
            }
            
            print(f"  Dictionary attack success: {dict_success_rate:.1f}%")
            print(f"  Brute force success: {brute_success_rate:.1f}%")
        
        return results
    
    def complexity_analysis(self):
        """
        Analyze password complexity and recommended security practices.
        
        Returns:
            Complexity analysis results
        """
        print("\n" + "=" * 70)
        print("PASSWORD COMPLEXITY ANALYSIS")
        print("=" * 70)
        
        analyzer = PasswordComplexityAnalyzer()
        
        # Generate passwords of different lengths
        print("\nGenerating passwords of different lengths...")
        
        results = {
            'length_4': {
                'count': 0,
                'avg_entropy': 0,
                'estimated_break_time': 'seconds'
            },
            'length_6': {
                'count': 0,
                'avg_entropy': 0,
                'estimated_break_time': 'minutes'
            },
            'length_8': {
                'count': 0,
                'avg_entropy': 0,
                'estimated_break_time': 'hours'
            },
            'length_12': {
                'count': 0,
                'avg_entropy': 0,
                'estimated_break_time': 'years'
            }
        }
        
        # Analyze different character sets
        char_sets = {
            'lowercase': string.ascii_lowercase,
            'alphanumeric': string.ascii_letters + string.digits,
            'complex': string.ascii_letters + string.digits + '!@#$%^&*()_+-='
        }
        
        for length in [4, 6, 8, 12]:
            for char_name, char_set in char_sets.items():
                print(f"\nPassword length {length}, {char_name} characters:")
                
                # Generate passwords
                passwords = analyzer.generate_passwords(length, char_set, count=100)
                results[f'length_{length}_{char_name}'] = {
                    'count': len(passwords),
                    'sample': passwords[:5],
                    'entropy': length * (len(char_set) / 8) / 8,
                    'crack_difficulty': self._estimate_crack_time(length, len(char_set))
                }
                
                print(f"  Sample: {passwords[:3]}")
                print(f"  Estimated crack time: {self._estimate_crack_time(length, len(char_set))}")
        
        return results
    
    def _estimate_crack_time(self, length, chars):
        """Estimate crack time based on password complexity."""
        entropy = length * (len(chars) / 8) / 8
        
        # Simplified estimation (actual times vary based on hardware)
        if entropy < 20:
            return 'seconds to minutes'
        elif entropy < 40:
            return 'hours to days'
        elif entropy < 60:
            return 'weeks to months'
        else:
            return 'years or more'
    
    def generate_test_hashes(self, password_list=None, hash_functions=None):
        """
        Generate test hashes from password list.
        
        Args:
            password_list: List of passwords to hash
            hash_functions: List of hash functions to use
        
        Returns:
            List of (password, hash, hash_function) tuples
        """
        if password_list is None:
            password_list = ['password', 'admin', 'test123', 'qwerty']
        
        if hash_functions is None:
            hash_functions = ['md5', 'sha1', 'sha256', 'pbkdf2_sha256']
        
        hashes = []
        for pwd in password_list:
            for hash_func in hash_functions:
                hashed, salt = PasswordHasher.hash_password(pwd, hash_func)
                hashes.append({
                    'password': pwd,
                    'hash': hashed,
                    'hash_function': hash_func,
                    'salt': salt
                })
        
        return hashes
    
    def save_report(self, filepath='security_report.txt'):
        """Generate and save security analysis report."""
        print(f"\nGenerating security report...")
        
        # Run analyses
        hash_analysis = self.hash_function_analysis()
        attack_comparison = self.attack_effectiveness_comparison()
        complexity = self.complexity_analysis()
        
        # Generate report
        report_lines = [
            "=" * 70,
            "PASSWORD SECURITY ANALYSIS REPORT",
            "=" * 70,
            "",
            "Generated by Password Cracker Project",
            f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "=" * 70,
            "1. HASH FUNCTION SECURITY ANALYSIS",
            "=" * 70,
            ""
        ]
        
        for hash_func, data in hash_analysis.items():
            report_lines.extend([
                f"Hash Function: {hash_func}",
                f"  Average Hash Time: {data['average_time_ms']:.2f}ms",
                f"  Salt Used: {data['has_salt']} ({data['salt_size']} bytes)",
                f"  Security Level: {data['security_level']}",
                f"  Recommendation: {data['recommendation']}",
                ""
            ])
        
        report_lines.extend([
            "=" * 70,
            "2. ATTACK EFFECTIVENESS COMPARISON",
            "=" * 70,
            ""
        ])
        
        for hash_func, data in attack_comparison.items():
            report_lines.extend([
                f"Hash Function: {hash_func}",
                f"  Dictionary Attack Success Rate: {data['dictionary_attack_success']:.1f}%",
                f"  Brute Force Success Rate: {data['brute_force_success']:.1f}%",
                f"  Passwords Tested: {data['passwords_tested']}",
                ""
            ])
        
        report_lines.extend([
            "=" * 70,
            "3. PASSWORD COMPLEXITY RECOMMENDATIONS",
            "=" * 70,
            "",
            "RECOMMENDATIONS:",
            "  - Use minimum 12 characters for passwords",
            "  - Mix uppercase, lowercase, numbers, and special characters",
            "  - Avoid common words and patterns",
            "  - Use password managers to generate strong passwords",
            "  - Enable two-factor authentication where possible",
            "  - Use bcrypt or argon2 for password hashing",
            "  - Never use MD5 or SHA1 for password storage",
            "",
            "=" * 70,
            "END OF REPORT",
            "=" * 70
        ])
        
        report = '\n'.join(report_lines)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"Report saved to: {filepath}")
        return report


def main():
    """Run main analysis."""
    
    # Initialize analyzer
    analyzer = SecurityAnalyzer()
    
    # Run analyses
    hash_analysis = analyzer.hash_function_analysis()
    
    # Generate test hashes
    test_hashes = analyzer.generate_test_hashes()
    
    # Save report
    analyzer.save_report()
    
    print("\nAnalysis completed successfully!")
    print("Run: python analysis.py")
    print("Or: python password_cracker.py")


if __name__ == '__main__':
    main()
