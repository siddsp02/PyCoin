"""Utility functions for conversions and parsing."""

import doctest
import struct
from datetime import datetime
from hashlib import sha256
from typing import Iterator, Literal, TypeVar

T = TypeVar("T")

Bit = Literal[0, 1]


def sha256d(b: bytes) -> bytes:
    """Two rounds of sha256."""
    return sha256(sha256(b).digest()).digest()


def swap_ordering(hexstr: str) -> str:
    """Returns a copy of a hex string with the byte order reversed."""
    return bytes.fromhex(hexstr)[::-1].hex()


def datetime_to_hex(
    date: datetime, prefixed: bool = False, reverse: bool = False
) -> str:
    """Returns a hex timestamp given a datetime object.

    If set to True, the 'prefixed' argument will keep the '0x'
    prefix in the hex string.
    """
    ret = f"{int(date.timestamp()):{'#x' if prefixed else 'x'}}"
    return swap_ordering(ret) if reverse else ret


def timestamp_to_hex(
    timestamp: float, prefixed: bool = False, reverse: bool = False
) -> str:
    """Returns a hex timestamp when given an integer or float.

    If set to True, the 'prefixed' argument will keep the '0x'
    prefix in the hex string.
    """
    ret = f"{int(timestamp):{'#x' if prefixed else 'x'}}"
    return swap_ordering(ret) if reverse else ret


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


def int_to_bytes_le(x: int) -> bytes:
    """Convert an integer to bytes (little endian)."""
    return x.to_bytes(bytelength(x), byteorder="little")


def int_to_bytes_be(x: int) -> bytes:
    """Convert an integer to bytes (big endian)."""
    return x.to_bytes(bytelength(x), byteorder="big")


def encode_base58(s: bytes) -> str:
    """Encodes a bytes object to base58 format.

    References:
        - https://www.oreilly.com/library/view/programming-bitcoin/9781492031482/ch04.html
    """
    BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    zeros = s.rindex(0) + 1
    assert all(not char for char in s[:zeros])
    res = ""
    num = int.from_bytes(s, byteorder="big")
    while num > 0:
        num, mod = divmod(num, 58)
        res = BASE58_ALPHABET[mod] + res
    return "1" * zeros + res

if __name__ == "__main__":
    doctest.testmod()
