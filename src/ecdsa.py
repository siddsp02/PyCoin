# !usr/bin/env python3

import multiprocessing as mp
import random
import struct
import time

from secp256k1 import CURVE, Point
from utils import bytelength, extract_bits, sha256d

WORKERS = mp.cpu_count()

p, a, b, G, n, h = CURVE

G = Point.from_int(G)


def generate(privkey: int, message: bytes = b"") -> tuple[int, int]:
    """Signs a message when given a private key, returning the signature of
    the signed message in the form of a an integer pair (r, s).

    References:
        - https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    """
    message_hash = sha256d(message)
    z = extract_bits(message_hash, start=0, end=256)
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
    message_hash = sha256d(message)
    z = extract_bits(message_hash, start=0, end=256)
    (r, s) = signature
    s1 = pow(s, -1, n)
    u1, u2 = (z * s1) % n, (r * s1) % n
    (x, y, z) = point = u1 * G + u2 * pubkey
    if point == (0, 1, 0):
        return False
    (x, y) = point.affine()  # type: ignore
    return r == x % n


def encode(signature: tuple[int, int]) -> bytes:
    """Returns a DER signature when given a signature pair (r, s).

    References:
        - https://bitcoin.stackexchange.com/questions/12554/
    """
    (r, s) = signature
    r_size, s_size = bytelength(r), bytelength(s)
    r_prefix, *r = r.to_bytes(r_size, byteorder="big")
    s_prefix, *s = s.to_bytes(s_size, byteorder="big")
    r, s = bytes(r), bytes(s)
    # Formatted strings for packing the byte values of the signature.
    r_fmt, s_fmt = f"B{r_size-1}s", f"B{s_size-1}s"
    # If the most significant byte of r and s are greater than 0x7F,
    # values are left-padded with the pad byte 0x00 by convention.
    if r_prefix > 0x7F:
        r_fmt = "!x" + r_fmt
    if s_prefix > 0x7F:
        s_fmt = "!x" + s_fmt
    # Re-pack our signature bytes based on the new format string.
    r = struct.pack(r_fmt, r_prefix, r)
    s = struct.pack(s_fmt, s_prefix, s)
    r_size, s_size = len(r), len(s)
    # For the 1st byte (0-based-indexing) of our message, the value
    # is the length of the remaining data used in the DER signature.
    ec_size = 1 + r_size + 2 + s_size + 1
    sig_fmt = f"!4B{r_size}s2B{s_size}sB"
    sighash = 0x00  # This needs to be assigned.
    return struct.pack(
        sig_fmt, 0x30, ec_size, 0x02, r_size, r, 0x02, s_size, s, sighash
    )


def decode(signature: bytes) -> tuple[int, int]:
    """Returns the decoded signature pair of a DER-encoded signature.

    References:
        - https://bitcoin.stackexchange.com/questions/12554/
    """
    header, ec_size = struct.unpack_from("!2B", signature)
    if ec_size != len(signature) - 3:
        raise ValueError("Signature has invalid encoding length.")
    if header != 0x30:
        raise ValueError("Signature does not have proper header prefix.")
    int_flag, r_size = struct.unpack_from("!2B", signature, offset=2)
    if int_flag != 0x02:
        raise ValueError("Signature not properly encoded.")
    r, int_flag, s_size = struct.unpack_from(f"!{r_size}sBB", signature, offset=4)
    if int_flag != 0x02:
        raise ValueError("Signature not properly encoded.")
    s, sighash = struct.unpack_from(f"!{s_size}sB", signature, offset=4 + r_size + 2)
    assert sighash == 0x00  # TODO: Change valid sighash value.
    r = int.from_bytes(r, byteorder="big")
    s = int.from_bytes(s, byteorder="big")
    return (r, s)


def generate_sigs(amount: int) -> list:
    cores = mp.cpu_count()
    msgs = [random.randbytes(10)] * amount
    keys = [random.randint(1, n - 1) for _ in range(amount)]
    pubkeys = [k * G for k in keys]
    with mp.Pool() as pool:
        sigs = pool.starmap(generate, zip(keys, msgs), chunksize=amount // cores)
    return list(zip(sigs, pubkeys, msgs))


def verify_sigs(params: list) -> list:
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

if __name__ == "__main__":
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
