#!/usr/bin/env python3
"""
Simulace útoků na hesla – BPC-AKR
Autoři: Zdeněk Ondra, Lukáš Makovička, Jiří Pokluda

Spuštění: python main.py
"""

import os
import string
import time

from src.hashers import ALGORITHMS
from src.database import create_entry, load_database
from src.attacker import dictionary_attack, brute_force_attack, load_wordlist
from src.rainbow import (
    CHAIN_LENGTH, PASSWORD_LENGTH, CHARSET,
    build_table, rainbow_attack, _hash,
)
from src.analyzer import (
    measure_hash_speed, password_entropy,
    brute_force_charset_size, format_time, print_attack_summary,
)


def section(title):
    print("\n" + "=" * 65, flush=True)
    print(f"  {title}", flush=True)
    print("=" * 65, flush=True)


def step(msg):
    print(f"\n  >>> {msg}", flush=True)


def run_hash_comparison():
    section("1. POROVNÁNÍ HASHOVACÍCH FUNKCÍ")
    print(f"\n  {'Algoritmus':<18} {'ms/hash':>10} {'hashů/s':>12}  Bezpečnost", flush=True)
    print("  " + "-" * 58, flush=True)

    security = {
        'md5':          'KRITICKÁ  – kryptograficky zlomený',
        'sha1':         'NÍZKÁ     – nevhodný pro hesla',
        'sha256':       'STŘEDNÍ   – rychlý, nevhodný bez soli',
        'sha512':       'STŘEDNÍ   – rychlý, nevhodný bez soli',
        'bcrypt':       'VYSOKÁ    – navržen pro hesla, cost factor',
        'pbkdf2_sha256':'VYSOKÁ    – 100 000 iterací, NIST doporučení',
    }

    speeds = {}
    fast = [a for a in ALGORITHMS if a not in ('bcrypt', 'pbkdf2_sha256')]
    slow = [a for a in ALGORITHMS if a in ('bcrypt', 'pbkdf2_sha256')]

    for alg in fast:
        print(f"  Měřím {alg}...", end='\r', flush=True)
        speeds[alg] = measure_hash_speed(alg, n=500)
    for alg in slow:
        print(f"  Měřím {alg} (pomalý, chvíli čekejte)...", end='\r', flush=True)
        speeds[alg] = measure_hash_speed(alg, n=5)

    print(" " * 60, end='\r')
    for alg in ALGORITHMS:
        r = speeds[alg]
        print(f"  {alg:<18} {r['ms_per_hash']:>10.3f} {r['hashes_per_sec']:>12.0f}  {security[alg]}", flush=True)

    print()
    print("  Klíčový poznatek: bcrypt/pbkdf2 jsou ~1 000–100 000× pomalejší", flush=True)
    print("  než MD5/SHA. To dramaticky zpomaluje brute-force útoky.", flush=True)

    return speeds


def run_dictionary_attack(wordlist_file, db_file):
    section("2. SLOVNÍKOVÝ ÚTOK")

    wordlist = load_wordlist(wordlist_file)
    print(f"\n  Wordlist: {wordlist_file} ({len(wordlist)} hesel)", flush=True)

    all_entries = load_database(db_file)
    entries_sha   = [e for e in all_entries if e['algorithm'] in ('sha256', 'md5', 'sha512')]
    entries_bcrypt = [e for e in all_entries if e['algorithm'] == 'bcrypt']
    print(f"  Databáze: {db_file} ({len(all_entries)} záznamů)", flush=True)

    print(f"\n  Slovník: {len(wordlist)} hesel", flush=True)
    print(f"  Testovací záznamy: {len(entries_sha)} (sha256) + {len(entries_bcrypt)} (bcrypt)", flush=True)

    print("\n  --- sha256 + sůl ---", flush=True)
    step("Spouštím slovníkový útok na sha256...")
    r_sha = dictionary_attack(entries_sha, wordlist)
    s_sha = print_attack_summary(r_sha, 'sha256')

    print("\n  --- bcrypt ---", flush=True)
    step("Spouštím slovníkový útok na bcrypt (pomalejší)...")
    r_bc = dictionary_attack(entries_bcrypt, wordlist)
    s_bc = print_attack_summary(r_bc, 'bcrypt')

    print()
    print(f"  Rychlost sha256:  {s_sha['attempts']/s_sha['elapsed']:,.0f} pokusů/s")
    if s_bc['elapsed'] > 0:
        print(f"  Rychlost bcrypt:  {s_bc['attempts']/s_bc['elapsed']:,.0f} pokusů/s")
    print("  → Bcrypt je řádově pomalejší → slovníkový útok trvá mnohem déle.")

    return s_sha, s_bc


def run_brute_force():
    section("3. ÚTOK HRUBOU SILOU")

    charset = string.ascii_lowercase + string.digits
    short_passwords = ['ab', 'aa', 'a1', 'zz', 'abc', 'a1b']

    print(f"\n  Znakový set: malá písmena + číslice ({len(charset)} znaků)")
    print(f"  Testovací hesla: {short_passwords}  (délka 2–3)")
    print(f"  Max. délka hledání: 4 znaky")

    results = {}
    for alg in ['md5', 'sha256', 'bcrypt']:
        entries = [create_entry(p, p, alg) for p in short_passwords]
        max_len = 3 if alg == 'bcrypt' else 4
        print(f"\n  --- {alg} ---", flush=True)
        if alg == 'bcrypt':
            step("bcrypt je pomalý (~14 hashů/s) – průběh vidíte níže:")
        else:
            step(f"Spouštím brute-force útok ({alg})...")
        r = brute_force_attack(entries, charset=charset, max_length=max_len)
        summary = print_attack_summary(r, alg)
        results[alg] = summary

    print()
    print("  Závislost počtu kombinací na délce hesla (36 znaků):")
    print(f"  {'Délka':>6}  {'Kombinace':>14}  {'čas MD5 (odhad)':>18}  {'čas SHA256':>18}")
    print("  " + "-" * 62)

    md5_speed = results['md5']['attempts'] / results['md5']['elapsed'] if results['md5']['elapsed'] > 0 else 1e6
    sha_speed = results['sha256']['attempts'] / results['sha256']['elapsed'] if results['sha256']['elapsed'] > 0 else 5e5

    for n in range(1, 9):
        combos = 36 ** n
        t_md5 = format_time(combos / md5_speed)
        t_sha = format_time(combos / sha_speed)
        print(f"  {n:>6}  {combos:>14,}  {t_md5:>18}  {t_sha:>18}")

    return results


def run_rainbow_tables():
    section("4. RAINBOW TABLES ÚTOK")

    print(f"\n  Prostor hesel: {len(CHARSET)} znaků, délka {PASSWORD_LENGTH} → {len(CHARSET)**PASSWORD_LENGTH:,} hesel")
    print(f"  Parametry tabulky: 1 500 řetězců × délka {CHAIN_LENGTH}")
    print(f"  Hashování: MD5 bez soli")
    print()

    step("Sestavuji rainbow table (výpočet řetězců)...")
    t0 = time.time()
    table = build_table(num_chains=1500, chain_length=CHAIN_LENGTH)
    build_time = time.time() - t0
    print(f"  Hotovo za {build_time:.2f} s  |  {len(table)} řetězců uloženo", flush=True)

    test_pwds = ['abc', 'xyz', 'aaa', 'mno', 'zzz', 'bcd', 'fgh', 'rst']
    entries = [{'username': p, 'hash': _hash(p), 'password': p} for p in test_pwds]

    print(f"\n  Testovací hesla: {test_pwds}")
    results = rainbow_attack(entries, table, chain_length=CHAIN_LENGTH)

    cracked = sum(1 for r in results if r['found'] is not None)
    print(f"\n  Prolomeno: {cracked}/{len(results)}")
    for r in results:
        status = f"'{r['found']}'" if r['found'] else "NEÚSPĚCH"
        pwd = r['entry']['password']
        print(f"    MD5('{pwd}') = {r['entry']['hash'][:16]}...  →  {status}  ({r['elapsed']:.3f}s)")

    print()
    print("  --- Vliv soli na rainbow tables ---")
    print("  Bez soli: stejné heslo → stejný hash → lze použít rainbow table.")
    print("  Se solí:  každé heslo dostane unikátní sůl → 'heslo+sůl1' a 'heslo+sůl2'")
    print("            dávají zcela jiné hashe. Tabulka by musela být")
    print("            předpočítána pro každou sůl → prakticky nemožné.")

    return {'cracked': cracked, 'total': len(results), 'build_time': build_time}


def run_complexity_analysis(speeds):
    section("5. SLOŽITOST HESEL A ODHADOVANÁ DOBA PROLOMENÍ")

    md5_rate = speeds['md5']['hashes_per_sec']
    sha256_rate = speeds['sha256']['hashes_per_sec']
    bcrypt_rate = speeds['bcrypt']['hashes_per_sec']

    test_passwords = [
        'ab', 'abc', 'abcd', 'abcde',
        'password', 'abc123', 'Abc123', 'P@ssw0rd',
        'Tr0ub4dor&3', 'correct-horse-battery-staple',
    ]

    print(f"\n  {'Heslo':<30} {'Délka':>5} {'Entropie':>9}  {'MD5':>14}  {'SHA256':>14}  {'bcrypt':>14}")
    print("  " + "-" * 92)

    for pwd in test_passwords:
        entropy = password_entropy(pwd)
        k = brute_force_charset_size(pwd)
        max_attempts = k ** len(pwd)
        t_md5    = format_time(max_attempts / md5_rate)
        t_sha    = format_time(max_attempts / sha256_rate)
        t_bcrypt = format_time(max_attempts / bcrypt_rate)
        print(f"  {pwd:<30} {len(pwd):>5} {entropy:>8.1f}b  {t_md5:>14}  {t_sha:>14}  {t_bcrypt:>14}")

    print()
    print("  Entropie E = n × log₂(k),  kde n = délka, k = velikost znakového prostoru.")
    print("  Časy jsou odhady pro průměrný CPU; GPU je 100–1000× rychlejší.")
    print("  Bcrypt s cost factorem 10 ≈ 100–200 ms/hash → výrazně zpomaluje útok.")


def main():
    print("=" * 65)
    print("  SIMULACE ÚTOKŮ NA HESLA")
    print("  BPC-AKR  |  Ondra, Makovička, Pokluda")
    print("=" * 65)

    print()

    while True:
        wordlist_file = input("  Cesta k wordlistu    (Enter = wordlist.txt):        ").strip() or 'wordlist.txt'
        if os.path.isfile(wordlist_file):
            break
        print(f"  Soubor '{wordlist_file}' nenalezen, zkuste znovu.")

    while True:
        db_file = input("  Cesta k databázi     (Enter = passwords_sample.db): ").strip() or 'passwords_sample.db'
        if os.path.isfile(db_file):
            break
        print(f"  Soubor '{db_file}' nenalezen, zkuste znovu.")

    speeds = run_hash_comparison()
    s_sha, s_bc = run_dictionary_attack(wordlist_file, db_file)
    brute_results = run_brute_force()
    rainbow_results = run_rainbow_tables()
    run_complexity_analysis(speeds)

    section("SHRNUTÍ VÝSLEDKŮ")
    print(f"  Slovníkový útok (sha256): {s_sha['cracked']}/{s_sha['total']} prolomeno")
    print(f"  Slovníkový útok (bcrypt): {s_bc['cracked']}/{s_bc['total']} prolomeno")
    print(f"  Hrubá síla (sha256):      {brute_results['sha256']['cracked']}/{brute_results['sha256']['total']} prolomeno")
    print(f"  Rainbow tables (MD5):     {rainbow_results['cracked']}/{rainbow_results['total']} prolomeno")
    print()
    print("  DOPORUČENÍ PRO BEZPEČNÉ UKLÁDÁNÍ HESEL:")
    print("  • Používat bcrypt nebo PBKDF2 (pomalé funkce odolné vůči GPU útokům)")
    print("  • Vždy přidat unikátní kryptografickou sůl pro každé heslo")
    print("  • Minimální délka hesla 12 znaků s kombinací typů znaků")
    print("  • Zakázat nejběžnější hesla (slovníkový útok)")
    print("  • MD5 a SHA-1 jsou pro ukládání hesel zcela nevhodné")


if __name__ == '__main__':
    main()
