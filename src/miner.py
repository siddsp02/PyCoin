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
import struct
from ctypes import Structure, c_char, c_uint32
from dataclasses import dataclass
from functools import partial, reduce, singledispatch
from operator import iadd
from typing import Self, SupportsBytes

try:
    from .constants import UINT32_MAX
    from .merkle import hash_tree
    from .utils import bytes_to_int_little, int_to_varint, sha256d
except ImportError:
    from constants import UINT32_MAX
    from merkle import hash_tree
    from utils import bytes_to_int_little, int_to_varint, sha256d


def list_to_bytes(lst: list[SupportsBytes]) -> bytes:
    ret = bytearray()
    ret += int_to_varint(len(lst))
    return reduce(iadd, map(bytes, lst), ret)


class BlockHeader(Structure):
    _fields_ = [
        ("version", c_uint32),
        ("prev_block", c_char * 32),
        ("merkle_root", c_char * 32),
        ("timestamp", c_uint32),
        ("bits", c_uint32),
        ("nonce", c_uint32),
    ]

    def __repr__(self) -> str:
        attrs = dict(self._fields_)
        vals = map(partial(getattr, self), attrs)
        return "{}({})".format(
            type(self).__name__, ", ".join(map("{}={}".format, attrs, vals))
        )

    @property
    def target(self) -> int:
        p = self.bits & 0xFFFFFF
        q = (self.bits & 0xFF000000) >> 24
        return p * 2 ** (8 * (q - 3))

    @property
    def hash(self) -> bytes:
        """The hash of the block header."""
        return sha256d(memoryview(self))

    @classmethod
    def from_json(cls, filename: str, fields: dict[str, int] | None = None) -> Self:
        """Returns a new BlockHeader instance by parsing a JSON."""
        return cls.from_buffer(parse_block_json(filename, fields))

    def verify(self) -> bool:
        """Checks if the block header is valid."""
        return bytes_to_int_little(self.hash) < self.target

    def _check_nonce(self, nonce: int) -> bool:
        """Checks a nonce to see if a valid hash is produced.
        This modifies the original struct.
        """
        self.nonce = nonce
        return self.verify()


# class ScriptSig:
#     ...


@dataclass
class TxIn:
    prev_tx_hash: bytes
    prev_tx_out_index: int
    script: bytes
    sequence: int = UINT32_MAX

    def __bytes__(self) -> bytes:
        return b""


@dataclass
class TxOut:
    value: int
    script: bytes

    def __bytes__(self) -> bytes:
        return b""


@dataclass
class Tx:
    version: int
    inputs: list[TxIn]
    outputs: list[TxOut]
    lock_time: int

    @property
    def valid(self) -> bool:
        ...

    @property
    def hash(self) -> bytes:
        """The transaction hash/id."""
        return sha256d(bytes(self))

    def __bytes__(self) -> bytes:
        ret = struct.pack("<L", self.version)
        ret += list_to_bytes(self.inputs)  # type: ignore
        ret += list_to_bytes(self.outputs)  # type: ignore
        ret += struct.pack("<L", self.lock_time)
        return ret


@dataclass
class Block:
    magic: int
    header: BlockHeader
    txs: list[Tx]

    @property
    def merkle_root(self) -> bytes:
        self._update_merkle_root()
        return self.header.merkle_root

    hash = merkle_root

    @property
    def blocksize(self) -> int:
        ...

    def add(self, tx: Tx) -> None:
        """Adds a transaction to the block."""
        # This needs to be updated to check for transaction validity.
        self.txs.append(tx)
        self._update_merkle_root()

    def _update_merkle_root(self) -> None:
        self.header.merkle_root = hash_tree(tx.hash for tx in self.txs)


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
    def _(value: int, offset: int = 0) -> None:  # type: ignore
        struct.pack_into("<I", header, offset, value)

    # Parse JSON fields, and pack the values
    # into the bytearray of the block header.
    with open(filename, "r") as f:
        block: dict = json.load(f)
        for key in block.keys() & fields.keys():
            pack_bytes(block[key], fields[key])
    return header
