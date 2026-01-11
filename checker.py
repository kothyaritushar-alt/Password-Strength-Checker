#!/usr/bin/env python3
"""
Password Strength Checker (CLI)
--------------------------------
A small, defensive security tool that evaluates password strength and provides
clear recommendations. Intended for educational and portfolio use only.

Usage:
  python checker.py "MyP@ssw0rd!"
  python checker.py            # interactive mode
  python checker.py --json     # JSON output
"""

import argparse
import json
import math
import re
import sys
from collections import Counter

# Small, intentionally limited list of common passwords
# (Do NOT include leaked datasets in public repositories)
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "abc123",
    "111111", "1234567890", "password1", "iloveyou"
}

SEQUENTIAL_SETS = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789"
]


def calculate_entropy(password: str) -> float:
    """Estimate Shannon entropy (in bits) for the password."""
    if not password:
        return 0.0
    counts = Counter(password)
    length = len(password)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy * length, 2)


def has_sequential_pattern(password: str, min_length: int = 3) -> bool:
    """Detect simple sequential patterns like abc, 123, or cba."""
    for seq in SEQUENTIAL_SETS:
        for i in range(len(seq) - min_length + 1):
            sub = seq[i:i + min_length]
            if sub in password or sub[::-1] in password:
                return True
    return False


def analyze_password(password: str) -> dict:
    """Analyze password strength and return structured results."""
    result = {
        "length": len(password),
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_special": bool(re.search(r"[^A-Za-z0-9]", password)),
        "is_common": password.lower() in COMMON_PASSWORDS,
        "has_repetition": bool(re.search(r"(.)\1{2,}", password)),
        "has_sequence": has_sequential_pattern(password),
        "entropy_bits": calculate_entropy(password),
        "score": 0,
        "verdict": "",
        "recommendations": []
    }

    score = 0

    # Length scoring
    if result["length"] >= 16:
        score += 30
    elif result["length"] >= 12:
        score += 20
    elif result["length"] >= 8:
        score += 10
    else:
        result["recommendations"].append("Increase password length (minimum 12 characters recommended).")

    # Character variety scoring
    score += 10 if result["has_lowercase"] else 0
    score += 10 if result["has_uppercase"] else 0
    score += 10 if result["has_digit"] else 0
    score += 10 if result["has_special"] else 0

    # Weakness penalties
    if result["is_common"]:
        score -= 40
        result["recommendations"].append("Avoid commonly used passwords.")

    if result["has_repetition"]:
        score -= 10
        result["recommendations"].append("Avoid repeated characters (e.g., 'aaa').")

    if result["has_sequence"]:
        score -= 10
        result["recommendations"].append("Avoid sequential patterns (e.g., '1234', 'abcd').")

    # Entropy guidance
    if result["entropy_bits"] < 28:
        score -= 10
        result["recommendations"].append("Password entropy is low; use a longer, more random password.")

    # Clamp score
    score = max(0, min(score, 100))
    result["score"] = score

    # Verdict mapping
    if score < 20:
        verdict = "Very Weak"
    elif score < 40:
        verdict = "Weak"
    elif score < 60:
        verdict = "Moderate"
    elif score < 80:
        verdict = "Strong"
    else:
        verdict = "Very Strong"

    result["verdict"] = verdict

    # General recommendation
    if score < 60:
        result["recommendations"].append(
            "Consider using a long passphrase or a password manager to generate strong passwords."
        )

    return result


def print_human_readable(result: dict):
    """Pretty-print the analysis for terminal output."""
    print("\nPassword Strength Analysis")
    print("----------------------------")
    print(f"Length            : {result['length']}")
    print(f"Entropy (bits)    : {result['entropy_bits']}")
    print(f"Score             : {result['score']} / 100")
    print(f"Verdict           : {result['verdict']}")
    print("\nCharacteristics:")
    print(f"  Lowercase letters : {result['has_lowercase']}")
    print(f"  Uppercase letters : {result['has_uppercase']}")
    print(f"  Digits            : {result['has_digit']}")
    print(f"  Special chars     : {result['has_special']}")

    if result["recommendations"]:
        print("\nRecommendations:")
        for rec in result["recommendations"]:
            print(f" - {rec}")


def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("password", nargs="?", help="Password to evaluate")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")
    args = parser.parse_args()

    if args.password:
        password = args.password
    else:
        try:
            password = input("Enter password to evaluate: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            sys.exit(1)

    analysis = analyze_password(password)

    if args.json:
        print(json.dumps(analysis, indent=2))
    else:
        print_human_readable(analysis)


if __name__ == "__main__":
    main()
