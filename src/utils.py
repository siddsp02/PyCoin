"""Utility functions for conversions and parsing."""

from dataclasses import dataclass
import doctest
import hashlib
import struct
from datetime import datetime
from hashlib import sha256
from itertools import pairwise
from typing import Callable, Iterator, Literal, Sequence, TypeVar

try:
    from constants import UINT16_MAX, UINT32_MAX, UINT64_MAX
except ImportError:
    from .constants import UINT16_MAX, UINT32_MAX, UINT64_MAX

T = TypeVar("T")
U = TypeVar("U")
V = TypeVar("V")

Bit = Literal[0, 1]


def modinv(a: int, n: int) -> int:
    """Returns the modular inverse of a and n."""
    return pow(a, -1, n)


def ripemd160(b: bytes) -> bytes:
    """Returns the RIPEMD160 hash of a buffer."""
    return hashlib.new("ripemd160", b).digest()


def sha256d(b: bytes) -> bytes:
    """Two rounds of sha256."""
    return sha256(sha256(b).digest()).digest()


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256d(b))


def int_to_varint(value: int) -> bytes:
    if value < 0 or value > UINT64_MAX:
        raise ValueError("Argument out of range.")

    if value < 0xFD:
        return bytes([value])

    if value <= UINT16_MAX:
        pref, fmt = 0xFD, "<BH"
    elif value <= UINT32_MAX:
        pref, fmt = 0xFE, "<BL"
    else:
        pref, fmt = 0xFF, "<BQ"

    return struct.pack(fmt, pref, value)


def flip(func: Callable[[T, U], V]) -> Callable[[U, T], V]:
    """Returns a new version of a function with the arguments flipped.

    Examples:
    >>> from operator import concat
    >>> concat("abc", "def")
    'abcdef'
    >>> concat = flip(concat)
    >>> concat("abc", "def")
    'defabc'
    """

    def wrapper(p, q):
        return func(q, p)

    return wrapper


def split(seq: Sequence[T], n: int) -> Iterator[Sequence[T]]:
    for i, j in pairwise(range(0, len(seq), len(seq) // n)):
        yield seq[i:j]


def bits(n: int, reverse: bool = False) -> Iterator[Bit]:
    return map(int, f"{n:b}"[::-1] if reverse else f"{n:b}")  # type: ignore


def vectorize_bits(n: int) -> list[Bit]:
    """Returns a list of the bits of an integer n."""
    return list(bits(n))  # type: ignore


def extract_bits(data: bytes, start: int = 0, end: int = 0) -> int:
    """Extracts the bits of a bytes object, returning its integer value.
    Note that value indices are extracted from MSB to LSB, so the order
    of bits is parsed from left to right.
    **This is likely going to be removed and replaced with bitwise
    operations, but I followed the pseudocode to avoid potential
    errors or issues.**

    Examples:
    >>> x = 0b1111010100000011
    >>> x_bytes = x.to_bytes(16, byteorder="big")
    >>> extract_bits(x_bytes, start=0, end=8)
    245
    >>> x = 0b1110101011000001
    >>> x_bytes = x.to_bytes(16, byteorder="big")
    >>> extract_bits(x_bytes, start=0, end=4)
    14
    """
    value = int.from_bytes(data, byteorder="big")
    bitvector = vectorize_bits(value)[start:end]
    bitstring = "".join(map(str, bitvector))
    return int(bitstring, base=2)


def bytelength(x: int) -> int:
    """Returns the length of an integer in bytes.

    References:
        - https://stackoverflow.com/questions/14329794/
    """
    return (x.bit_length() + 7) // 8


def partition(seq: Sequence[T], index: int) -> tuple[Sequence[T], Sequence[T]]:
    return seq[:index], seq[index:]


def int_to_bytes_little(x: int) -> bytes:
    """Convert an integer to bytes (little endian)."""
    return x.to_bytes(bytelength(x), byteorder="little")


def int_to_bytes_big(x: int) -> bytes:
    """Convert an integer to bytes (big endian)."""
    return x.to_bytes(bytelength(x), byteorder="big")


def bytes_to_int_little(x: bytes) -> int:
    """Convert bytes to an integer (little endian)."""
    return int.from_bytes(x, byteorder="little")


def bytes_to_int_big(x: bytes) -> int:
    """Convert bytes to an integer (big endian)."""
    return int.from_bytes(x, byteorder="big")


def uint256_to_bytes_big(x: int) -> bytes:
    """Convert an unsigned 256 bit integer to bytes (big endian)."""
    return x.to_bytes(32, byteorder="big")


def timestamp() -> int:
    return int(datetime.utcnow().timestamp())


if __name__ == "__main__":
    doctest.testmod()
