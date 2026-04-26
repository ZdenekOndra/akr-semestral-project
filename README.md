# Simulace útoků na hesla – BPC-AKR

Autoři: Zdeněk Ondra, Lukáš Makovička, Jiří Pokluda

## Popis projektu

Aplikace simuluje reálné metody útoku na hashovaná hesla a vyhodnocuje odolnost různých hashovacích algoritmů. Implementovány jsou slovníkový útok, útok hrubou silou a útok pomocí rainbow tables. Součástí je i analýza závislosti doby prolomení na složitosti hesla.

## Instalace

```bash
pip install -r requirements.txt
```

## Vstupní soubory

| Soubor | Popis |
|--------|-------|
| `wordlist.txt` | Slovník hesel pro slovníkový útok (jedno heslo na řádek) |
| `passwords_sample.db` | Databáze hashovaných hesel ve formátu `username:algorithm:salt:hash` |

## Spuštění

```bash
python3 main.py
```

Program se při spuštění zeptá na cesty k wordlistu a databázi. Stisknutím Enter se použijí výchozí soubory (`wordlist.txt`, `passwords_sample.db`).

Poté automaticky projde všemi pěti sekcemi:

1. Porovnání hashovacích funkcí (MD5, SHA-1, SHA-256, SHA-512, bcrypt, PBKDF2)
2. Slovníkový útok (sha256 a bcrypt)
3. Útok hrubou silou (md5, sha256, bcrypt – bcrypt trvá cca 5 minut)
4. Rainbow tables útok (MD5 bez soli)
5. Analýza složitosti hesel a odhadovaná doba prolomení

Sekce s bcrypt brute-force trvá cca 5–6 minut (bcrypt je záměrně pomalý – ~14 hashů/s).

## Struktura projektu

```
akr-semestral-projekt/
├── main.py               # Hlavní skript – spouští všechny scénáře
├── requirements.txt      # Závislosti (bcrypt)
├── src/
│   ├── hashers.py        # Hashování hesel (MD5, SHA-*, bcrypt, PBKDF2)
│   ├── attacker.py       # Slovníkový útok a brute-force útok
│   ├── database.py       # Správa databáze hashovaných hesel
│   ├── rainbow.py        # Rainbow tables (sestavení + útok)
│   └── analyzer.py       # Měření rychlosti, entropie, formátování
└── Simulace útoků na hesla.pdf   # Dokumentace projektu
```

## Výsledky (měřeno na Apple M-series CPU)

| Metoda | Algoritmus | Výsledek | Rychlost |
|--------|-----------|---------|---------|
| Slovníkový útok | sha256+sůl | 10/10 (100 %) | ~864 000 pokusů/s |
| Slovníkový útok | bcrypt | 3/3 (100 %) | ~14 pokusů/s |
| Brute-force | sha256+sůl | 6/6 (100 %) | ~975 000 pokusů/s |
| Rainbow tables | MD5 (bez soli) | 6/8 (75 %) | — |

## Použité knihovny

- `hashlib` – standardní knihovna Pythonu (MD5, SHA-*, PBKDF2)
- `bcrypt` – hashování heslem odolné vůči GPU útokům
- `itertools` – generování kombinací pro brute-force
- `os`, `time`, `string`, `math` – standardní knihovny Pythonu
