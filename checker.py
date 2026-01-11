#!/usr/bin/env python3
"""
Password Strength Checker - simple CLI tool.

Usage:
  python checker.py "MyP@ssw0rd!"
  python checker.py         # prompts interactively
"""

from collections import Counter
import math
import argparse
import sys
import json
import re

# Small list of common passwords for quick checks (keep short and safe)
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "abc123",
    "111111", "1234567890", "1234567", "password1", "iloveyou"
}

SEQUENTIAL_PATTERNS = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789"
]


def entropy(s: str) -> float:
    """Estimate Shannon entropy (bits) of the password string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    ent = 0.0
    for _, c in counts.items():
        p = c / length
        ent -= p * math.log2(p)
    # Convert entropy per symbol into total bits
    return ent * length


def has_sequences(s: str, min_len=3) -> bool:
    """Detect simple sequential substrings like 'abcd' or '1234'."""
    for seq in SEQUENTIAL_PATTERNS:
        for i in range(len(seq) - min_len + 1):
            sub = seq[i:i + min_len]
            if sub in s or sub in s[::-1]:
                return True
    return False


def score_password(pw: str) -> dict:
    """Return a dictionary with scores, flags, and suggestions for a password."""
    result = {
        "password_length": len(pw),
        "has_lower": bool(re.search(r"[a-z]", pw)),
        "has_upper": bool(re.search(r"[A-Z]", pw)),
        "has_digit": bool(re.search(r"\d", pw)),
        "has_special": bool(re.search(r"[^\w\s]", pw)),
        "is_common": pw.lower() in COMMON_PASSWORDS,
        "has_repeat": bool(re.search(r"(.)\1{2,}", pw)),  # three or more repeated chars
        "has_sequence": has_sequences(pw),
        "entropy_bits": round(entropy(pw), 2),
        "score": 0,
        "verdict": "",
        "suggestions": []
    }

    # Base scoring by length
    length = result["password_length"]
    if length >= 16:
        result["score"] += 30
    elif length >= 12:
        result["score"] += 20
    elif length >= 8:
        result["score"] += 10
    else:
        result["score"] += 0

    # Character variety
    if result["has_lower"]:
        result["score"] += 10
    if result["has_upper"]:
        result["score"] += 10
    if result["has_digit"]:
        result["score"] += 10
    if result["has_special"]:
        result["score"] += 10

    # Deduct points for weak patterns
    if result["is_common"]:
        result["score"] -= 40
        result["suggestions"].append("Password is a commonly used password — do not use it.")
    if result["has_repeat"]:
        result["score"] -= 10
        result["suggestions"].append("Avoid long repeated characters (e.g., 'aaaa').")
    if result["has_sequence"]:
        result["score"] -= 10
        result["suggestions"].append("Avoid sequential patterns (e.g., 'abcd', '1234').")

    # Entropy-based suggestion
    if result["entropy_bits"] < 28:
        result["score"] -= 10
        result["suggestions"].append("Password entropy is low; use longer and more random characters.")
    elif result["entropy_bits"] < 50:
        result["suggestions"].append("Consider increasing length or adding varied character types.")

    # Clamp score
    result["score"] = max(min(result["score"], 100), 0)

    # Verdict
    sc = result["score"]
    if sc < 20:
        result["verdict"] = "Very Weak"
    elif sc < 40:
        result["verdict"] = "Weak"
    elif sc < 60:
        result["verdict"] = "Fair"
    elif sc < 80:
        result["verdict"] = "Strong"
    else:
        result["verdict"] = "Very Strong"

    # Final suggestions for low scores
    if sc < 60:
        if "Use a passphrase" not in result["suggestions"]:
            result["suggestions"].append("Use a long passphrase (3+ random words) or a password manager.")
        if "Avoid common words" not in result["suggestions"]:
            result["suggestions"].append("Avoid common words or easily guessable patterns.")

    return result


def pretty_print(res: dict, hide_password=False):
    print("Password analysis:")
    if not hide_password:
        print(f"  Password (masked): {('*' * 6) if res.get('password_length') else ''}")
    print(f"  Length: {res['password_length']}")
    print(f"  Contains: "
          f"{'lower ' if res['has_lower'] else ''}"
          f"{'upper ' if res['has_upper'] else ''}"
          f"{'digit ' if res['has_digit'] else ''}"
          f"{'special' if res['has_special'] else ''}")
    print(f"  Entropy (bits): {res['entropy_bits']}")
    print(f"  Score: {res['score']} / 100")
    print(f"  Verdict: {res['verdict']}")
    if res['suggestions']:
        print("\nSuggestions:")
        for s in res['suggestions']:
            print(f" - {s}")


def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("password", nargs="?", help="Password to evaluate (wrap in quotes)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")
    args = parser.parse_args()

    if args.password:
        pw = args.password
    else:
        try:
            pw = input("Enter password to check: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            sys.exit(1)

    res = score_password(pw)
    # attach length again for masking display
    res['password_length'] = len(pw)

    if args.json:
        print(json.dumps(res, indent=2))
        return

    if args.quiet:
        print(f"{res['score']}")
        return

    pretty_print(res, hide_password=True)


if __name__ == "__main__":
    main()
