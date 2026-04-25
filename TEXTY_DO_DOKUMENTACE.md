# Texty k doplnění do dokumentace

Níže jsou připraveny texty pro všechny chybějící části dokumentace.
Zkopíruj je do Word dokumentu a exportuj jako PDF.

---

## Sekce 4.5 – Složitost hesel a entropie

Složitost hesla je určena dvěma faktory: délkou hesla a velikostí znakového prostoru, ze kterého jsou znaky vybírány. Entropie hesla H se vypočítá podle vzorce:

**H = n × log₂(k)**

kde *n* je délka hesla a *k* je velikost znakového prostoru (počet možných znaků).

Heslo složené pouze z malých písmen (k = 26) má nižší entropii než heslo stejné délky využívající malá a velká písmena, číslice a speciální znaky (k = 94). Například heslo „password" (8 znaků, pouze malá písmena) dosahuje entropie 37,6 bitů, zatímco „P@ssw0rd" (8 znaků, smíšené typy) dosahuje 52,4 bitů – přičemž vyšší entropie znamená exponenciálně delší dobu pro prolomení útočníkem.

---

## Sekce 4.6 – Rizika a jejich mitigace

Hlavní rizika spojená s ukládáním hesel a opatření pro jejich zmírnění:

- **Únik databáze** – v případě kompromitace serveru útočník získá přístup k hashům. Ochrana: použití pomalých hashovacích funkcí (bcrypt, Argon2), které zpomalují offline útoky.
- **Slovníkový útok** – útočník zkouší nejběžnější hesla a jejich varianty. Ochrana: vyžadovat složitá hesla, blokovat nejpoužívanější hesla.
- **Rainbow tables** – předpočítané tabulky hashů umožňují rychlé vyhledání hesla. Ochrana: unikátní kryptografická sůl pro každé heslo znemožní využití předpočítaných tabulek.
- **Brute-force útok** – systematické zkoušení všech kombinací. Ochrana: bcrypt nebo PBKDF2 s vysokým počtem iterací, čímž se každý pokus prodraží na řádově delší dobu.

---

## Sekce 4.7 – Shrnutí

Pro bezpečné ukládání hesel je nezbytné kombinovat více ochranných mechanismů. Samotné hashování bez soli je nedostatečné – sůl musí být unikátní pro každé heslo. Hashovací funkce musí být záměrně pomalé (bcrypt, PBKDF2), aby brute-force a slovníkové útoky byly časově nákladné. Rychlé funkce jako MD5 nebo SHA-256 jsou pro ukládání hesel zcela nevhodné, přestože jsou kryptograficky robustní pro jiné účely.

---

## Kapitola 5 – Realizace projektu

*(Tato kapitola nahrazuje původní „Aktuální stav a návrh dalšího postupu")*

### 5.1 Architektura řešení

Aplikace je implementována v jazyce Python 3 a je rozdělena do modulů dle principu oddělení zodpovědností (separation of concerns). Vstupním bodem je skript `main.py`, který orchestruje postupné spouštění všech simulačních scénářů.

**Moduly:**
- `src/hashers.py` – implementace hashování s i bez soli pro všechny podporované algoritmy
- `src/database.py` – vytváření, ukládání a načítání záznamů hashované databáze hesel
- `src/attacker.py` – implementace slovníkového útoku a útoku hrubou silou
- `src/rainbow.py` – sestavení rainbow table a vyhledávání pomocí redukčních funkcí
- `src/analyzer.py` – měření rychlosti hashování, výpočet entropie, formátování výstupů

Tok dat v aplikaci: `main.py` → vytvoří testovací záznamy (`database.py`) → spustí útoky (`attacker.py`, `rainbow.py`) → vyhodnotí a zobrazí výsledky (`analyzer.py`).

### 5.2 Popis vstupů, výstupů a potřebných souborů

**Vstupní soubory:**

| Soubor | Popis | Povinný |
|--------|-------|---------|
| `requirements.txt` | Závislosti pro instalaci (`bcrypt`) | Ano |
| `wordlist.txt` | Slovník 157 nejčastějších hesel pro slovníkový útok (UTF-8, jedno heslo na řádek) | Ne – aplikace má záložní interní seznam |
| `passwords_sample.db` | Ukázková databáze 14 hashovaných hesel ve formátu `username:algorithm:salt:hash` | Ne – aplikace generuje testovací záznamy interně |

Při spuštění aplikace jsou soubory `wordlist.txt` a `passwords_sample.db` automaticky detekovány a použity, pokud existují. Jinak se aplikace spustí s interně generovanými daty.

Ukázka formátu `passwords_sample.db`:
```
alice:sha256:a3f1c9d2...:7b36223a...
karl:bcrypt:$2b$10$...:$2b$10$...
```

**Výstupy:**
- Všechny výsledky jsou vypisovány na standardní výstup (terminál) průběžně v reálném čase.
- Výstup je strukturován do pěti sekcí: porovnání hashů, slovníkový útok, brute-force, rainbow tables, analýza složitosti.
- Závěrečné shrnutí sumarizuje počet prolomených hesel a bezpečnostní doporučení.
- Žádný výstupní soubor není generován – výsledky jsou určeny pro přímé čtení v terminálu.

### 5.3 Popis implementovaných algoritmů

**Slovníkový útok** (`dictionary_attack`)
Pro každý záznam v databázi postupně hashuje hesla ze slovníku a porovnává výsledný hash s uloženým. Díky paralelnímu procházení slovníku je tento útok velmi efektivní proti slabým heslům – pravděpodobnost úspěchu závisí na kvalitě slovníku.

**Útok hrubou silou** (`brute_force_attack`)
Systematicky generuje všechny kombinace znaků z definovaného znakového prostoru (charset) od délky 1 do `max_length`. Průběh útoku je průběžně vypisován na terminál. Počet kombinací roste exponenciálně s délkou hesla: pro znakový prostor 36 znaků a délku 8 je to 2,8 × 10¹² kombinací.

**Rainbow tables** (`build_table`, `lookup`)
Rainbow table je kompromisem mezi pamětí a výpočetním časem. Tabulka se skládá z řetězců délky `CHAIN_LENGTH`, kde se střídají operace hash a redukce:

`p₀ →(hash)→ h₀ →(reduce₀)→ p₁ →(hash)→ h₁ →(reduce₁)→ ... → pₙ`

Uloženy jsou pouze počáteční a koncové hodnoty každého řetězce. Při útoku se hledaný hash zpětně prochází řetězcem a hledá se shoda s koncem některého uloženého řetězce. Redukční funkce `_reduce(hash, step)` mapuje hash na heslo z prohledávaného prostoru s offsetem `step`, aby různé pozice v řetězci produkovaly různé redukce a zamezovaly cyklům.

**Implementace funguje výhradně na nesolených hashích** – sůl by znemožnila předpočítání, protože pro každou hodnotu soli by byla nutná samostatná tabulka.

### 5.4 Seznam použitých externích knihoven

| Knihovna | Verze | Účel |
|----------|-------|------|
| `bcrypt` | ≥ 4.0 | Hashování hesel algoritmem bcrypt (Blowfish-based) |
| `hashlib` | stdlib | MD5, SHA-1, SHA-256, SHA-512, PBKDF2-HMAC (součást Pythonu) |
| `itertools` | stdlib | Generování kartézského součinu pro brute-force |
| `os`, `time`, `math`, `string` | stdlib | Systémové operace, měření času, výpočty |

Žádná knihovna určená přímo pro prolomení hesel ani hotové implementace rainbow tables nebyly použity.

### 5.5 Architekturní a vývojové diagramy

*(Do Word dokumentu vložte níže popsané diagramy – lze nakreslit v draw.io, Lucidchart nebo LibreOffice Draw)*

**Diagram 1 – Architektura modulů**

```
main.py
├── src/hashers.py      ← hash_password(), verify_password()
├── src/database.py     ← create_entry(), save/load_database()
├── src/attacker.py     ← dictionary_attack(), brute_force_attack()
├── src/rainbow.py      ← build_table(), lookup(), rainbow_attack()
└── src/analyzer.py     ← measure_hash_speed(), password_entropy(), format_time()
```

**Diagram 2 – Tok dat slovníkového útoku**

```
Slovník hesel → [hash_password(kandidát)] → porovnat s DB hashem → nalezeno/pokračovat
```

**Diagram 3 – Tok dat rainbow table**

```
Sestavení: start_pwd → hash → reduce(0) → hash → reduce(1) → ... → end_pwd
           {end_pwd: start_pwd} uloženo do tabulky

Útok:      hledaný_hash → reduce(k) → hash → reduce(k+1) → ... → end_candidate
           hledáme end_candidate v tabulce → dohledáme start → projdeme řetězec → heslo
```

---

## Kapitola 6 – Testování a vyhodnocení výsledků

### 6.1 Testovací metodika

Testování probíhalo na počítači s procesorem Apple M-series (ARM64) s operačním systémem macOS, Python 3.14. Každá sekce testu měří čas skutečnou systémovou funkcí `time.time()` s přesností na milisekundy.

Pro každou útočnou metodu byl vytvořen set testovacích záznamů s definovanými hesly a algoritmy, přičemž kód znal plaintext (pro ověření správnosti), ale útok ho nepoužíval – pracoval výhradně s uloženým hashem a solí.

**Měřené metriky:**
- Počet prolomených hesel (z celkového počtu testovacích záznamů)
- Celkový čas útoku v sekundách
- Rychlost útoku v pokusech za sekundu

### 6.2 Výsledky testů

**Porovnání hashovacích funkcí:**

| Algoritmus | Čas / hash | Hashů/s | Bezpečnostní hodnocení |
|-----------|-----------|--------|----------------------|
| MD5 | 0,002 ms | 449 261 | KRITICKÁ – kryptograficky zlomený |
| SHA-1 | 0,002 ms | 472 971 | NÍZKÁ – nevhodný pro hesla |
| SHA-256 | 0,002 ms | 475 221 | STŘEDNÍ – bez soli nevhodný |
| SHA-512 | 0,002 ms | 453 242 | STŘEDNÍ – bez soli nevhodný |
| bcrypt | 70,0 ms | 14 | VYSOKÁ – navržen pro hesla |
| PBKDF2-SHA256 | 13,9 ms | 72 | VYSOKÁ – NIST doporučení |

Bcrypt je ~33 000× pomalejší než MD5/SHA, PBKDF2 ~6 600× pomalejší.

**Slovníkový útok** (slovník `wordlist.txt`, 157 hesel):

| Algoritmus | Prolomeno | Rychlost |
|-----------|----------|---------|
| SHA-256 + sůl | 10/10 (100 %) | 864 027 pokusů/s |
| bcrypt | 3/3 (100 %) | 14 pokusů/s |

Všechna testovací hesla pocházela ze slovníku – proto 100% úspěšnost. Klíčový rozdíl je rychlost: útok přes bcrypt byl ~60 000× pomalejší, přičemž u reálného slovníku o 14 milionech záznamech by útok na sha256 trval cca 16 sekund, na bcrypt přes 11 dní.

**Útok hrubou silou** (znakový prostor: a–z + 0–9, max. délka 4):

| Algoritmus | Prolomeno | Počet pokusů | Čas celkem |
|-----------|----------|------------|---------|
| MD5 | 6/6 (100 %) | 4 778 | 5,4 ms |
| SHA-256 | 6/6 (100 %) | 4 778 | 4,9 ms |
| bcrypt | 6/6 (100 %) | 4 778 | 5,6 min |

Testovací hesla měla délku 2–3 znaky, tedy útok uspěl vždy. Prodloužení délky hesla na 6 znaků (36⁶ = 2,1 mld. kombinací) by pro MD5 znamenalo ~40 minut, pro bcrypt ~4 roky.

**Rainbow tables** (MD5, hesla délky 3, malá písmena):

| Počet řetězců | Délka řetězce | Prolomeno | Čas sestavení |
|-------------|-------------|---------|-------------|
| 1 500 | 100 | 6/8 (75 %) | 2,07 s |

Dvě hesla nebyla nalezena – projevila se přirozená neúplnost rainbow tables (kolize při sestavování tabulky snižují efektivní pokrytí). Zvýšením počtu řetězců nebo jejich délky by se pokrytí přiblížilo 100 %.

**Analýza složitosti hesel:**

| Heslo | Délka | Entropie | Čas prolomení MD5 | Čas prolomení bcrypt |
|-------|-------|---------|-----------------|-------------------|
| ab | 2 | 9,4 bit | 1,5 ms | 47 s |
| abc | 3 | 14,1 bit | 39 ms | 20 min |
| password | 8 | 37,6 bit | 5,4 dní | 464 let |
| P@ssw0rd | 8 | 52,4 bit | 430 let | 13,5 mil. let |
| Tr0ub4dor&3 | 11 | 72,1 bit | 3,6 × 10⁸ let | 1,1 × 10¹³ let |
| correct-horse-battery-staple | 28 | 164 bit | 1,7 × 10³⁶ let | prakticky nikdy |

Výsledky potvrzují, že délka hesla a znakový prostor mají zásadní vliv na bezpečnost, a bcrypt navíc přidává řádový multiplikátor k době prolomení.

### 6.3 Shrnutí výsledků

Projekt úspěšně implementoval a otestoval tři metody útoku na hashovaná hesla. Klíčová zjištění:

1. **MD5 a SHA bez soli jsou zcela nevhodné** – útočník s GPU dokáže otestovat miliardy hashů za sekundu.
2. **Sůl zabrání rainbow tables** – bez soli je útok rainbow tables praktický; se solí je nutné sestavit tabulku pro každou individuální sůl.
3. **Bcrypt výrazně chrání i slabá hesla** – heslo „password" s bcrypt vydrží odolávat offline útoku stovky let, zatímco s MD5 pouhých 5 dní.
4. **Délka hesla je nejdůležitější faktor** – každý přidaný znak zvyšuje prostor kombinací k-násobně.

---

## Kapitola 7 – Závěr

Projekt splnil všechny stanovené cíle. Byl vytvořen nástroj v jazyce Python 3, který simuluje tři typy útoků na hashovaná hesla: slovníkový útok, útok hrubou silou a útok pomocí rainbow tables. Nástroj pracuje se šesti hashovacími algoritmy (MD5, SHA-1, SHA-256, SHA-512, bcrypt, PBKDF2) a umožňuje přímé porovnání jejich efektivity z pohledu útočníka.

Výsledky jasně demonstrují, proč jsou moderní pomalé hashovací funkce (bcrypt, PBKDF2) zásadní pro bezpečné ukládání hesel. Zároveň bylo ukázáno, jak i silné hashovací algoritmy jako SHA-256 mohou být zranitelné, pokud nejsou doplněny o kryptografickou sůl.

Projekt přináší praktické ověření teoretických poznatků z oblasti bezpečnosti hesel a může sloužit jako vzdělávací nástroj pro demonstraci důležitosti správného nakládání s uživatelskými přihlašovacími údaji.

---

## Kapitola 8 – Literatura

[1] OWASP Foundation. *Password Storage Cheat Sheet* [online]. 2024. Dostupné z: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

[2] PROVOS, Niels; MAZIÈRES, David. A Future-Adaptable Password Scheme. In: *USENIX Annual Technical Conference*. 1999, s. 32–32. ISBN neuvedeno.

[3] BONNEAU, Joseph. The science of guessing: analyzing an anonymized corpus of 70 million passwords. In: *2012 IEEE Symposium on Security and Privacy*. IEEE, 2012, s. 538–552. ISBN 978-0-7695-4681-0.

[4] PERCIVAL, Colin; JOSEFSSON, Simon. *The scrypt Password-Based Key Derivation Function*. RFC 7914 [online]. 2016. Dostupné z: https://www.rfc-editor.org/rfc/rfc7914

[5] IETF. *PKCS #5: Password-Based Cryptography Specification Version 2.1*. RFC 8018 [online]. 2017. Dostupné z: https://www.rfc-editor.org/rfc/rfc8018

---

## Poznámky k diagramům

Pro sekci 5.5 je potřeba vytvořit alespoň 2 diagramy (draw.io, MS Visio, nebo LibreOffice Draw):

**Diagram A – Architektura systému (blokový diagram):**
- Bloky: main.py (orchestrátor) → 4 moduly (hashers, attacker, rainbow, analyzer)
- Šipky znázorňující tok volání a dat

**Diagram B – Vývojový diagram slovníkového útoku:**
- Start → načíst slovník → pro každé heslo ze slovníku → hash(kandidát) == hash(cíl)? → Ano: vrátit heslo → Ne: další kandidát → konec slovníku → neúspěch

**Diagram C – Vývojový diagram rainbow table útoku:**
- Start → pro k od (délka_řetězce-1) do 0 → aplikuj reduce(k)...reduce(n-1) → end_candidate v tabulce? → Ano: projdi řetězec od start → ověř hash → Nalezeno/Ne → k--  → Nenalezeno

---

## Příloha – Reálný výstup programu

*(Lze vložit do dokumentace jako přílohu nebo do sekce 6 jako ukázku výstupu)*
*(Měřeno na: Apple M-series CPU, macOS, Python 3.14)*

```
=================================================================
  SIMULACE ÚTOKŮ NA HESLA
  BPC-AKR  |  Ondra, Makovička, Pokluda
=================================================================

=================================================================
  1. POROVNÁNÍ HASHOVACÍCH FUNKCÍ
=================================================================

  Algoritmus            ms/hash      hashů/s  Bezpečnost
  ----------------------------------------------------------
  md5                     0.002       449261  KRITICKÁ  – kryptograficky zlomený
  sha1                    0.002       472971  NÍZKÁ     – nevhodný pro hesla
  sha256                  0.002       475221  STŘEDNÍ   – rychlý, nevhodný bez soli
  sha512                  0.002       453242  STŘEDNÍ   – rychlý, nevhodný bez soli
  bcrypt                 70.029           14  VYSOKÁ    – navržen pro hesla, cost factor
  pbkdf2_sha256          13.932           72  VYSOKÁ    – 100 000 iterací, NIST doporučení

  Klíčový poznatek: bcrypt/pbkdf2 jsou ~1 000–100 000× pomalejší
  než MD5/SHA. To dramaticky zpomaluje brute-force útoky.

=================================================================
  2. SLOVNÍKOVÝ ÚTOK
=================================================================

  Wordlist: wordlist.txt (157 hesel)
  Databáze: passwords_sample.db (14 záznamů)

  --- sha256 + sůl ---

  Výsledek: 10/10 prolomeno (100%)
  Čas celkem: 0.1 ms
  Pokusů: 103  |  Rychlost: 864,027 /s
    [OK] password (sha256): 'password'  (0.000s)
    [OK] letmein (sha256): 'letmein'  (0.000s)
    [OK] monkey (sha256): 'monkey'  (0.000s)
    [OK] dragon (sha256): 'dragon'  (0.000s)
    [OK] sunshine (sha256): 'sunshine'  (0.000s)
    [OK] admin (sha256): 'admin'  (0.000s)
    [OK] root (sha256): 'root'  (0.000s)
    [OK] welcome (sha256): 'welcome'  (0.000s)
    [OK] test (sha256): 'test'  (0.000s)
    [OK] abc123 (sha256): 'abc123'  (0.000s)

  --- bcrypt ---

  Výsledek: 3/3 prolomeno (100%)
  Čas celkem: 917.4 ms
  Pokusů: 13  |  Rychlost: 14 /s
    [OK] password (bcrypt): 'password'  (0.070s)
    [OK] letmein (bcrypt): 'letmein'  (0.356s)
    [OK] monkey (bcrypt): 'monkey'  (0.491s)

  Rychlost sha256:  864,027 pokusů/s
  Rychlost bcrypt:  14 pokusů/s
  → Bcrypt je řádově pomalejší → slovníkový útok trvá mnohem déle.

=================================================================
  3. ÚTOK HRUBOU SILOU
=================================================================

  Znakový set: malá písmena + číslice (36 znaků)
  Testovací hesla: ['ab', 'aa', 'a1', 'zz', 'abc', 'a1b']  (délka 2–3)
  Max. délka hledání: 4 znaky

  --- md5 ---

  Výsledek: 6/6 prolomeno (100%)
  Čas celkem: 5.4 ms
  Pokusů: 4,778  |  Rychlost: 888,630 /s
    [OK] ab (md5): 'ab'  (0.000s)
    [OK] aa (md5): 'aa'  (0.000s)
    [OK] a1 (md5): 'a1'  (0.000s)
    [OK] zz (md5): 'zz'  (0.001s)
    [OK] abc (md5): 'abc'  (0.001s)
    [OK] a1b (md5): 'a1b'  (0.002s)

  --- sha256 ---

  Výsledek: 6/6 prolomeno (100%)
  Čas celkem: 4.9 ms
  Pokusů: 4,778  |  Rychlost: 975,723 /s
    [OK] ab (sha256): 'ab'  (0.000s)
    [OK] aa (sha256): 'aa'  (0.000s)
    [OK] a1 (sha256): 'a1'  (0.000s)
    [OK] zz (sha256): 'zz'  (0.001s)
    [OK] abc (sha256): 'abc'  (0.001s)
    [OK] a1b (sha256): 'a1b'  (0.002s)

  --- bcrypt ---

  Výsledek: 6/6 prolomeno (100%)
  Čas celkem: 5.6 min
  Pokusů: 4,778  |  Rychlost: 14 /s
    [OK] ab (bcrypt): 'ab'  (2.671s)
    [OK] aa (bcrypt): 'aa'  (2.588s)
    [OK] a1 (bcrypt): 'a1'  (4.548s)
    [OK] zz (bcrypt): 'zz'  (67.687s)
    [OK] abc (bcrypt): 'abc'  (97.100s)
    [OK] a1b (bcrypt): 'a1b'  (162.479s)

  Závislost počtu kombinací na délce hesla (36 znaků):
   Délka       Kombinace     čas MD5 (odhad)          čas SHA256
  --------------------------------------------------------------
       1              36              0.0 ms              0.0 ms
       2           1,296              1.5 ms              1.3 ms
       3          46,656             52.5 ms             47.8 ms
       4       1,679,616              1.89 s              1.72 s
       5      60,466,176             1.1 min             1.0 min
       6   2,176,782,336            40.8 min            37.2 min
       7  78,364,164,096             1.0 dní              22.3 h
       8  2,821,109,907,456            36.7 dní            33.5 dní

=================================================================
  4. RAINBOW TABLES ÚTOK
=================================================================

  Prostor hesel: 26 znaků, délka 3 → 17,576 hesel
  Parametry tabulky: 1 500 řetězců × délka 100
  Hashování: MD5 bez soli

  Sestavuji rainbow table...
  Hotovo za 2.07 s  |  338 řetězců uloženo

  Testovací hesla: ['abc', 'xyz', 'aaa', 'mno', 'zzz', 'bcd', 'fgh', 'rst']

  Prolomeno: 6/8
    MD5('abc') = 900150983cd24fb0...  →  'abc'  (0.006s)
    MD5('xyz') = d16fb36f0911f878...  →  'xyz'  (0.001s)
    MD5('aaa') = 47bce5c74f589f48...  →  NEÚSPĚCH  (0.014s)
    MD5('mno') = d1cf6a6090003989...  →  NEÚSPĚCH  (0.013s)
    MD5('zzz') = f3abb86bd34cf4d5...  →  'zzz'  (0.002s)
    MD5('bcd') = d4b7c284882ca9e2...  →  'bcd'  (0.002s)
    MD5('fgh') = 0f98df87c7440c04...  →  'fgh'  (0.002s)
    MD5('rst') = d674dfcd8b4db676...  →  'rst'  (0.001s)

  --- Vliv soli na rainbow tables ---
  Bez soli: stejné heslo → stejný hash → lze použít rainbow table.
  Se solí:  každé heslo dostane unikátní sůl → 'heslo+sůl1' a 'heslo+sůl2'
            dávají zcela jiné hashe. Tabulka by musela být
            předpočítána pro každou sůl → prakticky nemožné.

=================================================================
  5. SLOŽITOST HESEL A ODHADOVANÁ DOBA PROLOMENÍ
=================================================================

  Heslo                          Délka  Entropie             MD5          SHA256          bcrypt
  --------------------------------------------------------------------------------------------
  ab                                 2      9.4b          1.5 ms          1.4 ms         47.34 s
  abc                                3     14.1b         39.1 ms         37.0 ms        20.5 min
  abcd                               4     18.8b          1.02 s        961.6 ms           8.9 h
  abcde                              5     23.5b         26.45 s         25.00 s         9.6 dní
  password                           8     37.6b         5.4 dní         5.1 dní    4.64e+02 let
  abc123                             6     31.0b           1.3 h           1.3 h    4.83e+00 let
  Abc123                             6     35.7b         1.5 dní         1.4 dní    1.26e+02 let
  P@ssw0rd                           8     52.4b    4.30e+02 let    4.07e+02 let    1.35e+07 let
  Tr0ub4dor&3                       11     72.1b    3.57e+08 let    3.38e+08 let    1.12e+13 let
  correct-horse-battery-staple      28    164.0b    1.68e+36 let    1.59e+36 let    5.28e+40 let

  Entropie E = n × log₂(k),  kde n = délka, k = velikost znakového prostoru.
  Časy jsou odhady pro průměrný CPU; GPU je 100–1000× rychlejší.
  Bcrypt s cost factorem 10 ≈ 100–200 ms/hash → výrazně zpomaluje útok.

=================================================================
  SHRNUTÍ VÝSLEDKŮ
=================================================================
  Slovníkový útok (sha256): 10/10 prolomeno
  Slovníkový útok (bcrypt): 3/3 prolomeno
  Hrubá síla (sha256):      6/6 prolomeno
  Rainbow tables (MD5):     6/8 prolomeno

  DOPORUČENÍ PRO BEZPEČNÉ UKLÁDÁNÍ HESEL:
  • Používat bcrypt nebo PBKDF2 (pomalé funkce odolné vůči GPU útokům)
  • Vždy přidat unikátní kryptografickou sůl pro každé heslo
  • Minimální délka hesla 12 znaků s kombinací typů znaků
  • Zakázat nejběžnější hesla (slovníkový útok)
  • MD5 a SHA-1 jsou pro ukládání hesel zcela nevhodné
```
