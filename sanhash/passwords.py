import re
import time
from pathlib import Path
from .core import hash_bytes
from .identify import identify_hash

COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678",
    "123456789", "1234567890", "admin", "admin123", "qwerty",
    "qwerty123", "letmein", "welcome", "iloveyou", "abc123",
    "monkey", "dragon", "football", "master", "login"
}


def analyze_hash(target_hash, algorithm):
    target = target_hash.strip().lower()
    valid_hex = bool(target) and all(c in "0123456789abcdef" for c in target)
    expected_lengths = {label: hashlib_len for label, hashlib_len in {
        "MD5": 32, "SHA-1": 40, "SHA-224": 56, "SHA-256": 64,
        "SHA-384": 96, "SHA-512": 128, "SHA3-224": 56,
        "SHA3-256": 64, "SHA3-384": 96, "SHA3-512": 128,
        "BLAKE2b": 128, "BLAKE2s": 64
    }.items()}
    expected = expected_lengths.get(algorithm)
    identified = identify_hash(target)
    format_ok = valid_hex and expected == len(target) if expected else False
    return {
        "input_length": len(target),
        "character_set": "Hexadecimal" if valid_hex else "Invalid / non-hexadecimal",
        "expected_length": expected,
        "format_valid": format_ok,
        "possible_algorithms": identified,
        "algorithm_consistent": algorithm in identified or any(algorithm == x.split(" (")[0] for x in identified),
    }


def analyze_candidate(candidate):
    if not candidate:
        return {"score": 0, "rating": "UNKNOWN", "findings": []}
    findings = []
    lower = candidate.lower()
    score = 0
    if lower in COMMON_PASSWORDS:
        findings.append("Known/common password")
        score += 40
    if len(candidate) < 8:
        findings.append("Shorter than 8 characters")
        score += 25
    elif len(candidate) < 12:
        findings.append("Moderate length")
        score += 10
    if candidate.isalpha():
        findings.append("Letters only")
        score += 20
    if candidate.isdigit():
        findings.append("Digits only")
        score += 30
    if re.fullmatch(r"[A-Za-z]+\d+", candidate):
        findings.append("Simple letters + trailing digits pattern")
        score += 20
    if len(set(candidate)) <= max(3, len(candidate)//3):
        findings.append("Low character diversity")
        score += 15
    if re.search(r"(.)\1{2,}", candidate):
        findings.append("Repeated-character pattern")
        score += 15
    if re.search(r"0123|1234|2345|3456|4567|5678|6789|abcd|qwer", lower):
        findings.append("Sequential/common keyboard pattern")
        score += 20

    if score >= 60:
        rating = "VERY WEAK"
    elif score >= 35:
        rating = "WEAK"
    elif score >= 15:
        rating = "MODERATE"
    else:
        rating = "STRONGER CANDIDATE"
    return {"score": min(score, 100), "rating": rating, "findings": findings}


def dictionary_check(target_hash, algorithm, wordlist_path):
    target = target_hash.strip().lower()
    attempts = 0
    started = time.perf_counter()
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            candidate = line.rstrip("\r\n")
            if candidate == "":
                continue
            attempts += 1
            hashes = hash_bytes(candidate.encode("utf-8"))
            if hashes.get(algorithm, "").lower() == target:
                elapsed = max(time.perf_counter() - started, 1e-9)
                return {
                    "match": True,
                    "candidate": candidate,
                    "attempts": attempts,
                    "elapsed": elapsed,
                    "speed": attempts / elapsed,
                    "strength": analyze_candidate(candidate),
                }
    elapsed = max(time.perf_counter() - started, 1e-9)
    return {"match": False, "candidate": None, "attempts": attempts,
            "elapsed": elapsed, "speed": attempts / elapsed, "strength": None}
