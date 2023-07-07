# !usr/bin/env python3

"""The miner for Bitcoin. Works by guessing a nonce for the
block header, and then checking if the hash is less than the
target amount.

Transaction validation and full blocks will be added later on,
along with merkle tree hashing, difficulty adjustment, and
timestamp updates -- the whole thing.
"""

import json
import math
import multiprocessing as mp
import struct
import time
from ctypes import Structure, c_char, c_uint32
from functools import partial, singledispatch
from typing import Self

try:
    from .utils import bytes_to_int_le, sha256d
except ImportError:
    from utils import bytes_to_int_le, sha256d

WORKERS = mp.cpu_count()

UINT32_MAX = 0xFFFFFFFF


class Struct(Structure):
    def __repr__(self) -> str:
        attrs = dict(self._fields_)  # type: ignore
        vals = map(partial(getattr, self), attrs)
        return "{}({})".format(
            type(self).__name__, ", ".join(map("{}={}".format, attrs, vals))
        )

    def raw(self) -> memoryview:
        return memoryview(self)  # type: ignore


class BlockHeader(Struct):
    _fields_ = [
        ("version", c_uint32),
        ("prev_block", c_char * 32),
        ("merkle_root", c_char * 32),
        ("timestamp", c_uint32),
        ("bits", c_uint32),
        ("nonce", c_uint32),
    ]

    @property
    def target(self) -> int:
        p = self.bits & 0xFFFFFF
        q = (self.bits & 0xFF000000) >> 24
        return p * 2 ** (8 * (q - 3))

    @property
    def hash(self) -> bytes:
        """The hash of the block header."""
        return sha256d(self.raw())

    @classmethod
    def from_json(cls, filename: str, fields: dict[str, int] | None = None) -> Self:
        """Returns a new BlockHeader instance by parsing a JSON."""
        return BlockHeader.from_buffer(parse_block_json(filename, fields))

    def verify(self) -> bool:
        """Checks if the block header is valid."""
        return bytes_to_int_le(self.hash) < self.target

    def _check_nonce(self, nonce: int) -> bool:
        """Checks a nonce to see if a valid hash is produced.
        This modifies the original struct.
        """
        self.nonce = nonce
        return self.verify()


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


def parse_block_json(filename: str, fields: dict[str, int] | None = None) -> bytearray:
    """Parses a JSON file of a block, converting the values into a bytearray."""

    if fields is None:
        fields = {
            "ver": 0,
            "prev_block": 4,
            "mrkl_root": 36,
            "time": 68,
            "bits": 72,
            "nonce": 76,
        }

    header = bytearray(80)

    @singledispatch
    def pack_bytes(value: str, offset: int = 0) -> None:
        struct.pack_into("<32s", header, offset, bytes.fromhex(value)[::-1])

    @pack_bytes.register
    def _(value: int, offset: int = 0) -> None:
        struct.pack_into("<I", header, offset, value)

    # Parse JSON fields, and pack the values
    # into the bytearray of the block header.
    with open(filename) as f:
        block: dict = json.load(f)
        for key in block.keys() & fields.keys():
            pack_bytes(block[key], fields[key])
    return header


if __name__ == "__main__":
    # This is just an example of mining the genesis block.
    # Mining works, but it is slow since looping in Python
    # is expensive.
    block = BlockHeader.from_json("example_blocks/genesis.json")
    start = 2_080_000_000
    t1 = time.perf_counter()
    with mp.Pool(processes=WORKERS) as pool:
        results = pool.imap(
            block._check_nonce, range(start, UINT32_MAX), chunksize=20_000
        )
        nonce = next((i for i, val in enumerate(results, start) if val), None)
    t2 = time.perf_counter()
    if nonce is None:
        print("Nonce not found.")
    else:
        print(f"Block mined with {nonce=}")
    print(f"Time taken = {t2-t1:.8f} seconds")
    if nonce is not None:
        print(f"Hashrate: {(nonce-start)//(t2-t1)} H/s")
