# !usr/bin/env python3

import multiprocessing as mp
import random
import struct
import time


try:
    from .secp256k1 import CURVE, Point
    from .utils import extract_bits, int_to_bytes_be, sha256d
except ImportError:
    from secp256k1 import CURVE, Point
    from utils import extract_bits, int_to_bytes_be, sha256d

WORKERS = mp.cpu_count()

p, a, b, g, n, h = CURVE

G = Point.from_int(g)


def generate(privkey: int, message: bytes = b"") -> tuple[int, int]:
    """Signs a message when given a private key, returning the signature of
    the signed message in the form of a an integer pair (r, s).

    References:
        - https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    """
    z = extract_bits(sha256d(message), start=0, end=256)
    (r, s) = (0, 0)  # Start with invalid values by default.
    while r == 0 or s == 0:
        k = random.randrange(1, n)
        (x, y) = (k * G).affine()  # type: ignore
        r = x % n
        s = pow(k, -1, n) * (z + r * privkey) % n
    return (r, s)


def verify(signature: tuple[int, int], pubkey: Point, message: bytes) -> bool:
    """Verifies that the message given was signed by the given public key.

    References:
        - https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    """
    if not pubkey.on_curve or pubkey == (0, 1, 0):
        return False
    z = extract_bits(sha256d(message), start=0, end=256)
    (r, s) = signature
    s1 = pow(s, -1, n)
    u1, u2 = (z * s1) % n, (r * s1) % n
    point = u1 * G + u2 * pubkey
    if point == (0, 1, 0):
        return False
    (x, y) = point.affine()  # type: ignore
    return r == x % n


def encode(sig: tuple[int, int]) -> bytes:
    """Returns a DER signature when given a signature pair (r, s).

    References:
        - https://bitcoin.stackexchange.com/questions/12554/
    """
    (r, s) = map(int_to_bytes_be, sig)
    if r[0] > 0x7F:
        r = b"\x00" + r
    if s[0] > 0x7F:
        s = b"\x00" + s
    size = 1 + 2 + len(r) + 2 + len(s)
    ret = bytearray(1 + size)
    fmt = f">4B{len(r)}s2B{len(s)}s"
    struct.pack_into(fmt, ret, 0, 0x30, size - 1, 0x2, len(r), r, 0x2, len(s), s)
    return ret


def decode(sig: bytes) -> tuple[int, int]:
    """Returns the decoded signature pair of a DER-encoded signature.

    References:
        - https://bitcoin.stackexchange.com/questions/12554/
    """
    offset = 3
    rlen = sig[offset]
    offset += 1
    rbin = sig[offset : offset + rlen]
    offset += rlen + 1
    slen = sig[offset]
    offset += 1
    sbin = sig[offset : offset + slen]
    r = int.from_bytes(rbin, byteorder="big")
    s = int.from_bytes(sbin, byteorder="big")
    return (r, s)


def generate_sigs(
    amount: int,
) -> list[tuple[tuple[int, int], tuple[int, ...] | int, bytes]]:
    cores = mp.cpu_count()
    msgs = [random.randbytes(10)] * amount
    keys = [random.randint(1, n - 1) for _ in range(amount)]
    pubkeys = [k * G for k in keys]
    with mp.Pool() as pool:
        sigs = pool.starmap(generate, zip(keys, msgs), chunksize=amount // cores)
    return list(zip(sigs, pubkeys, msgs))


def verify_sigs(
    params: list[tuple[tuple[int, int], tuple[int, ...] | int, bytes]]
) -> list[bool]:
    cores = mp.cpu_count()
    amount = len(params)
    with mp.Pool() as pool:
        results = pool.starmap(verify, params, chunksize=amount // cores)
    return results


# Signature verification is likely to be slow due to
# the inherent lack of speed for multiprecision math.
# On my 8 core machine, I was able to increase signature
# verification rate from ~50/s to ~2,000/s using Projective
# coordinates instead of affine coordinates, as well as
# parallel processing.
def main() -> None:
    # A small signature verification benchmark.
    amount = 10_000
    s = time.perf_counter()
    sigs = generate_sigs(amount)
    e = time.perf_counter()
    print(e - s)
    s = time.perf_counter()
    verified = verify_sigs(sigs)
    e = time.perf_counter()
    print(amount / (e - s))
    print(all(verified))


if __name__ == "__main__":
    main()
