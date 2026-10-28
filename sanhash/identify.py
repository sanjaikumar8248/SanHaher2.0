def identify_hash(value):
    h = value.strip().lower()
    if not h:
        return []
    if any(c not in "0123456789abcdef" for c in h):
        return []
    n = len(h)
    mapping = {
        32: ["MD5", "NTLM (possible)"],
        40: ["SHA-1", "RIPEMD-160 (possible)"],
        56: ["SHA-224", "SHA3-224 (possible)"],
        64: ["SHA-256", "SHA3-256", "BLAKE2s (possible)"],
        96: ["SHA-384", "SHA3-384 (possible)"],
        128: ["SHA-512", "SHA3-512", "BLAKE2b (possible)"],
    }
    return mapping.get(n, ["Unknown / unsupported format"])

def likelihood(label, raw):
    if "possible" in label.lower():
        return "Possible"
    return "High likelihood"
