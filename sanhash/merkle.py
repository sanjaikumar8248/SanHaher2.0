import hashlib

def sha256_hex(data: bytes):
    return hashlib.sha256(data).hexdigest()

def merkle_root(leaves):
    if not leaves:
        return None
    level = [bytes.fromhex(x) for x in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[i] + level[i+1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()

def merkle_layers(leaves):
    layers = []
    if not leaves:
        return layers
    level = [x for x in leaves]
    layers.append(level)
    while len(level) > 1:
        work = list(level)
        if len(work) % 2:
            work.append(work[-1])
        level = [
            sha256_hex(bytes.fromhex(work[i]) + bytes.fromhex(work[i+1]))
            for i in range(0, len(work), 2)
        ]
        layers.append(level)
    return layers
