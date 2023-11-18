import doctest
import struct
from typing import Iterator

C, D = 2, 4


def rotl64(n: int, b: int) -> int:
    return ((n << b) | n >> (64 - b)) % 2**64


def sipround(v0: int, v1: int, v2: int, v3: int) -> tuple[int, int, int, int]:
    v0 = (v0 + v1) % 2**64
    v1 = rotl64(v1, 13) ^ v0
    v0 = rotl64(v0, 32)
    v2 = (v2 + v3) % 2**64
    v3 = rotl64(v3, 16) ^ v2
    v2 = (v2 + v1) % 2**64
    v1 = rotl64(v1, 17) ^ v2
    v2 = rotl64(v2, 32)
    v0 = (v0 + v3) % 2**64
    v3 = rotl64(v3, 21) ^ v0
    return v0, v1, v2, v3


def parse_words(m: bytes) -> Iterator[int]:
    return (w[0] for w in struct.iter_unpack("<Q", m))


def siphash(k: bytes, m: bytes) -> int:
    """Implementation of siphash 2-4 in Python.

    Examples:
    >>> k = struct.pack("<2Q", 0x0706050403020100, 0x0F0E0D0C0B0A0908)
    >>> hex(siphash(k, bytes.fromhex("000102030405060708090a0b0c0d0e")))  # Example used in references.
    '0xa129ca6149be45e5'

    References:
        - https://cr.yp.to/siphash/siphash-20120918.pdf
    """
    assert len(k) == 16
    k0, k1 = struct.unpack("<2Q", k)
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573
    b = len(m)
    w = -(-(b + 1) // 8)
    m = m.ljust(w * 8, b"\0")
    assert len(m) % 8 == 0
    for i, m_i in enumerate(parse_words(m)):
        if i == w - 1:
            m_i |= (b % 256) << 56
        v3 ^= m_i
        for _ in range(C):
            v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0 ^= m_i
    v2 ^= 0xFF
    for _ in range(D):
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    return v0 ^ v1 ^ v2 ^ v3


if __name__ == "__main__":
    doctest.testmod()
