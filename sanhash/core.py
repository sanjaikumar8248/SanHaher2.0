import base64
import hashlib
import mimetypes
from pathlib import Path

ALGORITHMS = [
    ("MD5", "md5"),
    ("SHA-1", "sha1"),
    ("SHA-224", "sha224"),
    ("SHA-256", "sha256"),
    ("SHA-384", "sha384"),
    ("SHA-512", "sha512"),
    ("SHA3-224", "sha3_224"),
    ("SHA3-256", "sha3_256"),
    ("SHA3-384", "sha3_384"),
    ("SHA3-512", "sha3_512"),
    ("BLAKE2b", "blake2b"),
    ("BLAKE2s", "blake2s"),
]

def hash_bytes(data: bytes):
    result = {}
    for label, name in ALGORITHMS:
        h = hashlib.new(name)
        h.update(data)
        result[label] = h.hexdigest()
    return result

def hash_text(text: str):
    return hash_bytes(text.encode("utf-8"))

def hash_file(path, chunk_size=1024 * 1024):
    hashes = {label: hashlib.new(name) for label, name in ALGORITHMS}
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            for h in hashes.values():
                h.update(chunk)
    return {label: h.hexdigest() for label, h in hashes.items()}

def base64_text(text: str):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")

def file_info(path):
    p = Path(path)
    size = p.stat().st_size
    mime, _ = mimetypes.guess_type(p.name)
    return {
        "name": p.name,
        "size": size,
        "size_human": human_size(size),
        "mime": mime or "application/octet-stream",
        "extension": p.suffix.lower() or "none",
        "absolute_path": str(p.resolve()),
    }

def human_size(n):
    units = ["B", "KB", "MB", "GB", "TB"]
    x = float(n)
    for u in units:
        if x < 1024 or u == units[-1]:
            return f"{x:.1f} {u}" if u != "B" else f"{int(x)} B"
        x /= 1024


def brute_force_hash(target_hash, algorithm, charset, max_length, max_attempts=2_000_000):
    """Educational bounded brute-force recovery.

    Generates candidates in increasing length and compares their cryptographic
    hash with the supplied target. Returns progress/result metadata.
    """
    import itertools
    import time

    target = target_hash.strip().lower()
    start = time.perf_counter()
    attempts = 0
    checked_length = 0

    for length in range(1, int(max_length) + 1):
        checked_length = length
        for chars in itertools.product(charset, repeat=length):
            candidate = "".join(chars)
            attempts += 1

            h = hashlib.new(dict(ALGORITHMS)[algorithm], candidate.encode("utf-8"))
            if h.hexdigest().lower() == target:
                elapsed = max(time.perf_counter() - start, 1e-9)
                return {
                    "match": True,
                    "candidate": candidate,
                    "attempts": attempts,
                    "elapsed": elapsed,
                    "speed": attempts / elapsed,
                    "checked_length": checked_length,
                }

            if attempts >= max_attempts:
                elapsed = max(time.perf_counter() - start, 1e-9)
                return {
                    "match": False,
                    "stopped": True,
                    "reason": "Maximum attempt limit reached",
                    "candidate": candidate,
                    "attempts": attempts,
                    "elapsed": elapsed,
                    "speed": attempts / elapsed,
                    "checked_length": checked_length,
                }

    elapsed = max(time.perf_counter() - start, 1e-9)
    return {
        "match": False,
        "stopped": False,
        "reason": "Search space exhausted",
        "candidate": "",
        "attempts": attempts,
        "elapsed": elapsed,
        "speed": attempts / elapsed,
        "checked_length": checked_length,
    }
