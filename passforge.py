#!/usr/bin/env python3
"""
passforge.py — password generator and strength analyzer

Two jobs: generate passwords that aren't garbage, and tell you honestly
whether a password you already have is any good.

Usage:
    python passforge.py generate [options]
    python passforge.py check [password]
    python passforge.py check --interactive
"""

import argparse
import hashlib
import math
import os
import re
import secrets
import string
import sys

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False


# ── terminal helpers ──────────────────────────────────────────────────────────

def c(text, color):
    if not COLOR:
        return text
    colors = {
        "red":    Fore.RED,
        "green":  Fore.GREEN,
        "yellow": Fore.YELLOW,
        "cyan":   Fore.CYAN,
        "bold":   Style.BRIGHT,
        "dim":    Style.DIM,
    }
    return f"{colors.get(color, '')}{text}{Style.RESET_ALL}"


def banner():
    print(c("""
  ██████╗  █████╗ ███████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ██████╔╝███████║███████╗███████╗█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ██║     ██║  ██║███████║███████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
    """, "cyan"))
    print(c("  password generator + strength analyzer\n", "dim"))


# ── character pools ───────────────────────────────────────────────────────────

LOWERCASE  = string.ascii_lowercase
UPPERCASE  = string.ascii_uppercase
DIGITS     = string.digits
SYMBOLS    = "!@#$%^&*()-_=+[]{}|;:,.<>?"

# ambiguous chars that look similar across fonts — excluded when readability matters
AMBIGUOUS  = "0O1lI"


# ── generation ────────────────────────────────────────────────────────────────

def build_pool(use_upper, use_digits, use_symbols, exclude_ambiguous):
    pool = LOWERCASE
    if use_upper:
        pool += UPPERCASE
    if use_digits:
        pool += DIGITS
    if use_symbols:
        pool += SYMBOLS
    if exclude_ambiguous:
        pool = "".join(ch for ch in pool if ch not in AMBIGUOUS)
    return pool


def generate_password(length, use_upper, use_digits, use_symbols, exclude_ambiguous):
    pool = build_pool(use_upper, use_digits, use_symbols, exclude_ambiguous)

    if len(pool) < 2:
        raise ValueError("character pool is too small — enable more character types")

    # guarantee at least one character from each requested category
    # this prevents passwords like "aaaaaa" that technically use the pool
    required = [secrets.choice(LOWERCASE)]
    if use_upper:
        upper_pool = UPPERCASE if not exclude_ambiguous else "".join(c for c in UPPERCASE if c not in AMBIGUOUS)
        if upper_pool:
            required.append(secrets.choice(upper_pool))
    if use_digits:
        digit_pool = DIGITS if not exclude_ambiguous else "".join(c for c in DIGITS if c not in AMBIGUOUS)
        if digit_pool:
            required.append(secrets.choice(digit_pool))
    if use_symbols:
        required.append(secrets.choice(SYMBOLS))

    if length < len(required):
        raise ValueError(f"length {length} is too short for the selected character types (need at least {len(required)})")

    # fill the rest randomly, then shuffle — avoids predictable positions for required chars
    filler = [secrets.choice(pool) for _ in range(length - len(required))]
    combined = required + filler
    secrets.SystemRandom().shuffle(combined)
    return "".join(combined)


def generate_passphrase(word_count, separator, capitalize):
    # EFF large wordlist embedded as a small practical subset
    # for a real deployment you'd load the full 7776-word list from disk
    words = [
        "apple", "bridge", "cloud", "delta", "ember", "flame", "gravel", "harbor",
        "index", "jumper", "kite", "lemon", "marble", "noble", "ocean", "planet",
        "quartz", "river", "stone", "table", "umbra", "vapor", "winter", "xenon",
        "yonder", "zebra", "anchor", "basin", "coral", "dagger", "eagle", "forest",
        "glacier", "hollow", "iron", "jungle", "kernel", "lunar", "metal", "nether",
        "orbit", "prism", "quiver", "radar", "solar", "tower", "ultra", "vertex",
        "walnut", "xylem", "yellow", "zone", "amber", "bronze", "cedar", "drift",
        "echo", "frost", "gust", "haze", "inlet", "jade", "knoll", "lance",
        "marsh", "night", "onset", "patch", "quest", "ridge", "shelf", "thorn",
        "upper", "vault", "wheat", "xenial", "yarrow", "zeal", "abyss", "blaze",
        "crest", "dense", "exile", "flare", "grove", "haven", "ivory", "jolt"
    ]
    chosen = [secrets.choice(words) for _ in range(word_count)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    return separator.join(chosen)


# ── strength analysis ─────────────────────────────────────────────────────────

# common patterns that tank real-world strength regardless of entropy
KEYBOARD_WALKS   = ["qwerty", "asdf", "zxcv", "qazwsx", "123456", "654321"]
COMMON_FRAGMENTS = ["password", "pass", "admin", "login", "welcome", "letmein",
                    "monkey", "dragon", "master", "shadow", "abc", "iloveyou"]


def entropy_bits(password):
    pool_size = 0
    if re.search(r"[a-z]", password): pool_size += 26
    if re.search(r"[A-Z]", password): pool_size += 26
    if re.search(r"\d",    password): pool_size += 10
    if re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", password): pool_size += 32
    if pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


def repeated_chars(password):
    """Returns true if any char appears more than 40% of the time."""
    if not password:
        return False
    from collections import Counter
    counts = Counter(password.lower())
    return any(v / len(password) > 0.4 for v in counts.values())


def has_keyboard_walk(password):
    low = password.lower()
    return any(walk in low for walk in KEYBOARD_WALKS)


def has_common_fragment(password):
    low = password.lower()
    return any(frag in low for frag in COMMON_FRAGMENTS)


def has_leet_speak(password):
    """Detects obvious leet substitutions — passw0rd, p@ssword, etc."""
    normalized = password.lower()
    leet_map = {"0": "o", "1": "i", "3": "e", "@": "a", "$": "s", "4": "a", "5": "s"}
    for char, replacement in leet_map.items():
        normalized = normalized.replace(char, replacement)
    return any(frag in normalized for frag in COMMON_FRAGMENTS)


def check_hibp(password):
    """
    Checks the Have I Been Pwned API using k-anonymity.
    Only the first 5 chars of the SHA-1 hash are sent — the full password never leaves.
    Returns breach count or -1 on failure.
    """
    if not REQUESTS_AVAILABLE:
        return None  # can't check, not a failure

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=5
        )
        resp.raise_for_status()
    except requests.RequestException:
        return None  # network issue, skip silently

    for line in resp.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0


def analyze_password(password):
    """
    Returns a dict with all analysis results.
    Score is 0–100 — not a guarantee, just a reasonable heuristic.
    """
    results = {}

    results["length"]            = len(password)
    results["entropy"]           = entropy_bits(password)
    results["has_lower"]         = bool(re.search(r"[a-z]", password))
    results["has_upper"]         = bool(re.search(r"[A-Z]", password))
    results["has_digits"]        = bool(re.search(r"\d", password))
    results["has_symbols"]       = bool(re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", password))
    results["repeated_chars"]    = repeated_chars(password)
    results["keyboard_walk"]     = has_keyboard_walk(password)
    results["common_fragment"]   = has_common_fragment(password)
    results["leet_speak"]        = has_leet_speak(password)

    # base score from entropy (caps at 60 pts)
    score = min(60, int(results["entropy"] / 1.5))

    # length bonus
    if results["length"] >= 16: score += 10
    elif results["length"] >= 12: score += 5

    # diversity bonus
    diversity = sum([results["has_lower"], results["has_upper"],
                     results["has_digits"], results["has_symbols"]])
    score += diversity * 5

    # penalties
    if results["repeated_chars"]:  score -= 15
    if results["keyboard_walk"]:   score -= 20
    if results["common_fragment"]: score -= 25
    if results["leet_speak"]:      score -= 15
    if results["length"] < 8:      score -= 30

    results["score"] = max(0, min(100, score))

    # breach check — last because it's a network call
    results["breach_count"] = check_hibp(password)

    return results


def score_label(score):
    if score >= 80: return ("Excellent",  "green")
    if score >= 60: return ("Good",       "cyan")
    if score >= 40: return ("Fair",       "yellow")
    return             ("Weak",       "red")


def crack_time_estimate(entropy):
    """
    Rough estimate based on 10 billion guesses/second (fast offline attack).
    This isn't meant to be a precise number — it's a sense of scale.
    """
    guesses = 2 ** entropy
    seconds = guesses / 10_000_000_000

    if seconds < 1:        return "less than a second"
    if seconds < 60:       return f"{seconds:.0f} seconds"
    if seconds < 3600:     return f"{seconds/60:.1f} minutes"
    if seconds < 86400:    return f"{seconds/3600:.1f} hours"
    if seconds < 2592000:  return f"{seconds/86400:.1f} days"
    if seconds < 31536000: return f"{seconds/2592000:.1f} months"
    years = seconds / 31536000
    if years < 1_000:      return f"{years:.0f} years"
    if years < 1_000_000:  return f"{years/1000:.1f} thousand years"
    return                        f"{years:.2e} years"


# ── display ───────────────────────────────────────────────────────────────────

def print_analysis(password, results, show_password=True):
    label, label_color = score_label(results["score"])

    print()
    if show_password:
        print(f"  {'Password':<20} {c(password, 'bold')}")

    print(f"  {'Score':<20} {c(str(results['score']) + '/100', label_color)}  ({c(label, label_color)})")
    print(f"  {'Length':<20} {results['length']} characters")
    print(f"  {'Entropy':<20} {results['entropy']:.1f} bits")
    print(f"  {'Est. crack time':<20} {crack_time_estimate(results['entropy'])}  (offline, fast GPU)")

    print()
    print(c("  Character mix:", "dim"))
    checks = [
        ("Lowercase",  results["has_lower"]),
        ("Uppercase",  results["has_upper"]),
        ("Digits",     results["has_digits"]),
        ("Symbols",    results["has_symbols"]),
    ]
    for name, present in checks:
        tick = c("✓", "green") if present else c("✗", "red")
        print(f"    {tick}  {name}")

    print()
    print(c("  Pattern detection:", "dim"))
    flags = [
        ("Repeated characters",  results["repeated_chars"]),
        ("Keyboard walk",        results["keyboard_walk"]),
        ("Common word fragment", results["common_fragment"]),
        ("Leet-speak variant",   results["leet_speak"]),
    ]
    clean = True
    for name, found in flags:
        if found:
            print(f"    {c('⚠', 'yellow')}  {name} detected")
            clean = False
    if clean:
        print(f"    {c('✓', 'green')}  No obvious patterns found")

    print()
    bc = results.get("breach_count")
    if bc is None:
        print(f"  {c('?', 'dim')}  Breach check skipped (requests not installed or network error)")
    elif bc == 0:
        print(f"  {c('✓', 'green')}  Not found in known breach databases")
    else:
        print(f"  {c('!', 'red')}  {c(f'Found in {bc:,} breached records', 'red')}  — do not use this password")

    print()

    if results["score"] < 60:
        print(c("  Suggestions:", "yellow"))
        if results["length"] < 12:
            print("    → Use at least 12 characters (16+ is better)")
        if not results["has_upper"]:
            print("    → Add uppercase letters")
        if not results["has_digits"]:
            print("    → Add numbers")
        if not results["has_symbols"]:
            print("    → Add symbols like !@#$%")
        if results["common_fragment"] or results["leet_speak"]:
            print("    → Avoid dictionary words, even with letter substitutions")
        if results["keyboard_walk"]:
            print("    → Avoid keyboard patterns (qwerty, 12345, etc.)")
        print()


# ── CLI ───────────────────────────────────────────────────────────────────────

def cmd_generate(args):
    banner()

    if args.passphrase:
        for i in range(args.count):
            pw = generate_passphrase(args.words, args.separator, args.capitalize)
            print(f"  {c(pw, 'green')}")
            if args.analyze:
                results = analyze_password(pw)
                print_analysis(pw, results, show_password=False)
        return

    passwords = []
    for _ in range(args.count):
        pw = generate_password(
            length            = args.length,
            use_upper         = not args.no_upper,
            use_digits        = not args.no_digits,
            use_symbols       = not args.no_symbols,
            exclude_ambiguous = args.no_ambiguous,
        )
        passwords.append(pw)

    if args.count == 1:
        print(f"\n  {c(passwords[0], 'green')}\n")
        if args.analyze:
            results = analyze_password(passwords[0])
            print_analysis(passwords[0], results, show_password=False)
    else:
        print()
        for pw in passwords:
            print(f"  {c(pw, 'green')}")
        print()


def cmd_check(args):
    banner()

    if args.interactive or not args.password:
        import getpass
        print("  Enter password to analyze (input hidden):\n")
        try:
            password = getpass.getpass("  Password: ")
        except KeyboardInterrupt:
            print("\n  Aborted.")
            sys.exit(0)
    else:
        password = " ".join(args.password)  # handles passwords with spaces if quoted

    if not password:
        print(c("  No password provided.", "red"))
        sys.exit(1)

    results = analyze_password(password)
    print_analysis(password, results)


def main():
    parser = argparse.ArgumentParser(
        prog="passforge",
        description="password generator and strength analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python passforge.py generate
  python passforge.py generate --length 20 --count 5
  python passforge.py generate --no-symbols --no-ambiguous
  python passforge.py generate --passphrase --words 5
  python passforge.py check --interactive
  python passforge.py check 'MyP@ssw0rd!'
        """
    )

    sub = parser.add_subparsers(dest="command")

    # generate subcommand
    gen = sub.add_parser("generate", help="generate one or more passwords")
    gen.add_argument("--length",       type=int,  default=16, help="password length (default: 16)")
    gen.add_argument("--count",        type=int,  default=1,  help="number of passwords to generate")
    gen.add_argument("--no-upper",     action="store_true",   help="exclude uppercase letters")
    gen.add_argument("--no-digits",    action="store_true",   help="exclude digits")
    gen.add_argument("--no-symbols",   action="store_true",   help="exclude symbols")
    gen.add_argument("--no-ambiguous", action="store_true",   help="exclude visually ambiguous chars (0, O, 1, l, I)")
    gen.add_argument("--analyze",      action="store_true",   help="run strength analysis on generated password")
    gen.add_argument("--passphrase",   action="store_true",   help="generate a passphrase instead")
    gen.add_argument("--words",        type=int,  default=4,  help="word count for passphrases (default: 4)")
    gen.add_argument("--separator",    type=str,  default="-", help="word separator for passphrases (default: -)")
    gen.add_argument("--capitalize",   action="store_true",   help="capitalize each word in passphrase")

    # check subcommand
    chk = sub.add_parser("check", help="analyze the strength of a password")
    chk.add_argument("password",       nargs="*",             help="password to analyze (or use --interactive)")
    chk.add_argument("--interactive",  action="store_true",   help="prompt for password without echoing it")

    args = parser.parse_args()

    if args.command == "generate":
        cmd_generate(args)
    elif args.command == "check":
        cmd_check(args)
    else:
        banner()
        parser.print_help()


if __name__ == "__main__":
    main()
