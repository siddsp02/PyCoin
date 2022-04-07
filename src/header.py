from __future__ import annotations

import math
import struct

from .utils import sha256d


def verify(header: bytes) -> bool:
    """Verify a block header using the block hashing algorithm for Bitcoin."""
    hashed_header = sha256d(header)
    bits = struct.unpack_from("<I", header, offset=72)[0]
    return int.from_bytes(hashed_header, byteorder="little") < target(bits)


def difficulty(bits: int) -> float:
    """Returns the difficulty given the target in compact format.

    References:
        - https://en.bitcoin.it/wiki/Difficulty
    """
    exponent_diff = 8 * (0x1D - ((bits >> 24) & 0xFF))
    significand = bits & 0xFFFFFF
    return math.ldexp(0xFFFF / significand, exponent_diff)


def target(bits: int) -> int:
    """Returns the target given its compact format value.

    References:
        - https://en.bitcoin.it/wiki/Difficulty
    """
    p = bits & 0xFFFFFF
    q = (bits & 0xFF000000) >> 24
    return p * 2 ** (8 * (q - 3))


def hashrate_from_difficulty(diff: float) -> float:
    """Returns an estimate of the network hashrate when given
    the difficulty or target in non-compact form.
    """
    return (diff / 600) * 2**32
