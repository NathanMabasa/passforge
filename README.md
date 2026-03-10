# passforge
CLI tool that generates cryptographically secure passwords and analyzes strength through entropy scoring, pattern detection, and Have I Been Pwned breach lookups.

# Disclaimer

This tool is intended for personal use, security education, and authorized security testing only.

passforge is a password utility — it generates credentials and evaluates their strength. It does not perform any network attacks, credential stuffing, or unauthorized access.

Use responsibly.

# passforge

A command-line password generator and strength analyzer written in Python.

Generates cryptographically secure passwords and passphrases, then tells you honestly whether a given password is actually strong — not just whether it passes some checkbox policy.

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What it does

**Generate** — builds passwords using Python's `secrets` module (CSPRNG), not `random`. You control length, character sets, and whether to exclude visually ambiguous characters like `0/O` or `1/l`.

**Analyze** — scores any password across several dimensions:
- Shannon entropy (bits)
- Character diversity
- Pattern detection: keyboard walks, dictionary fragments, leet-speak substitutions, repeated characters
- Estimated crack time at 10B guesses/sec (offline, GPU attack)
- Have I Been Pwned lookup via k-anonymity (only a 5-char hash prefix leaves your machine)

---

## Install

```bash
git clone https://github.com/yourusername/passforge.git
cd passforge
pip install -r requirements.txt
```

Python 3.8+ required. `requests` and `colorama` are optional — the tool runs without them, just without color output and breach checking.

---

## Usage

### Generate a password

```bash
# default: 16 chars, all character types
python passforge.py generate

# longer, get 5 options
python passforge.py generate --length 24 --count 5

# no symbols, exclude ambiguous chars (useful for typed passwords)
python passforge.py generate --no-symbols --no-ambiguous

# generate and immediately analyze
python passforge.py generate --analyze
```

### Generate a passphrase

```bash
# 4 random words joined by dashes
python passforge.py generate --passphrase

# 6 capitalized words with underscores
python passforge.py generate --passphrase --words 6 --separator _ --capitalize
```

### Analyze a password

```bash
# check a password (visible in terminal history — use interactive mode for sensitive checks)
python passforge.py check 'MyP@ssword!'

# hidden input, doesn't appear in shell history
python passforge.py check --interactive
```

---

## Example output

```
  Score                90/100  (Excellent)
  Length               16 characters
  Entropy              104.9 bits
  Est. crack time      1.18e+14 years  (offline, fast GPU)

  Character mix:
    ✓  Lowercase
    ✓  Uppercase
    ✓  Digits
    ✓  Symbols

  Pattern detection:
    ✓  No obvious patterns found

  ✓  Not found in known breach databases
```

And for something weak:

```
  Score                7/100  (Weak)
  ...
  Pattern detection:
    ⚠  Common word fragment detected
    ⚠  Leet-speak variant detected

  !  Found in 9,545,824 breached records — do not use this password

  Suggestions:
    → Use at least 12 characters (16+ is better)
    → Add uppercase letters
    → Avoid dictionary words, even with letter substitutions
```

---

## How the breach check works

The HIBP check uses [k-anonymity](https://haveibeenpwned.com/API/v3#PwnedPasswords): the tool hashes your password with SHA-1, sends only the first 5 characters of that hash to the API, then checks the returned list of matches locally. Your actual password never leaves your machine.

```
SHA-1("password123") = CBFDAC6008F9CAB4083784CBD1874F76618D2A97
                                    ↑↑↑↑↑
Sent to API:              CBFDA  (only this)
Rest checked locally:           C6008F9CAB4...
```

---

## Notes on entropy vs. crack time

Entropy is a measure of unpredictability, not complexity. A 16-character truly random password has roughly 105 bits of entropy against a full keyspace attack. But crack time estimates assume the attacker is brute-forcing blind — dictionary attacks, credential stuffing, and targeted attacks work differently. The score penalizes patterns that make dictionary-style attacks viable.

---

## Options reference

```
generate:
  --length INT        password length (default: 16)
  --count INT         how many to generate
  --no-upper          exclude uppercase
  --no-digits         exclude digits
  --no-symbols        exclude symbols
  --no-ambiguous      exclude 0, O, 1, l, I
  --analyze           run strength check on output
  --passphrase        generate word-based passphrase instead
  --words INT         word count for passphrase (default: 4)
  --separator STR     word separator (default: -)
  --capitalize        capitalize each word

check:
  password            password as argument
  --interactive       hidden input via getpass
```

---

## Dependencies

```
requests>=2.28    # breach checking (optional)
colorama>=0.4     # color output (optional)
```

---

## License

MIT
