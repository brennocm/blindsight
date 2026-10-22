"""Pure-python secp256k1 public key recovery (research only, not constant-time)."""
from safehash import k

P = 2**256 - 2**32 - 977  # secp256k1 field prime
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        l = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        l = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)


def mul(pt, n):
    r = None
    while n:
        if n & 1: r = add(r, pt)
        pt = add(pt, pt); n >>= 1
    return r


def ecrecover(h: bytes, v: int, r: int, s: int) -> str:
    x = r
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y & 1) != (v - 27): y = P - y
    R = (x, y)
    z = int.from_bytes(h, "big")
    rinv = pow(r, -1, N)
    Q = mul(add(mul(R, s), mul(G, (-z) % N)), rinv)
    pub = Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
    return "0x" + k(pub)[12:].hex()


def safe_signers(safe_tx_hash_hex: str, signatures_hex: str):
    """Recover signers as the Safe contract does in checkSignatures (EOA + eth_sign kinds)."""
    h = bytes.fromhex(safe_tx_hash_hex[2:])
    sig = bytes.fromhex(signatures_hex[2:])
    out = []
    for i in range(0, len(sig) - len(sig) % 65, 65):
        r = int.from_bytes(sig[i:i + 32], "big"); s = int.from_bytes(sig[i + 32:i + 64], "big"); v = sig[i + 64]
        if v in (0, 1):
            out.append(("contract" if v == 0 else "approved_hash", "0x" + sig[i + 12:i + 32].hex()))
        elif v > 30:
            out.append(("eth_sign", ecrecover(k(b"\x19Ethereum Signed Message:\n32" + h), v - 4, r, s)))
        else:
            out.append(("eoa", ecrecover(h, v, r, s)))
    return out
