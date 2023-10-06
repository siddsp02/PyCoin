# !usr/bin/env python3

"""The miner for Bitcoin. Works by guessing a nonce for the
block header, and then checking if the hash is less than the
target amount.

Transaction validation and full blocks will be added later on,
along with merkle tree hashing, difficulty adjustment, and
timestamp updates -- the whole thing.
"""

from abc import ABC, abstractmethod
from itertools import accumulate, chain
import json
import math
from operator import concat
import struct
from dataclasses import dataclass
from functools import partial, singledispatch
from typing import Self, Sequence, SupportsBytes, Any

from ..encoding_schemes.varint import varint
from ..utils import bytes_to_int_little, sha256d
from .merkle import hash_tree


def list_to_bytes(values: Sequence[SupportsBytes], encode_size: bool = True) -> bytes:
    """Converts a list of binary types to a raw buffer of bytes.
    This encodes the length of the data using `varint` encoding.
    """
    size = len(values)
    ret = bytearray()
    if encode_size:
        ret += varint.read(size)
    ret += b"".join(map(bytes, values))
    return ret


class BinaryHashable(ABC):
    @abstractmethod
    def get_hash_data(self) -> bytes:
        ...

    @property
    def hash(self) -> bytes:
        return sha256d(self.get_hash_data())

    @abstractmethod
    def __bytes__(self) -> bytes:
        ...


def prepend(x, it):
    return chain((0,), it)


class BlockHeader(BinaryHashable):
    def __init__(
        self,
        version: int,
        prev_block: bytes,
        merkle_root: bytes,
        timestamp: int,
        bits: int,
        nonce: int,
    ) -> None:
        self._data = bytearray(80)
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    def __repr__(self) -> str:
        attrs = ["version", "prev_block", "merkle_root", "timestamp", "bits", "nonce"]
        vals = map(partial(getattr, self), attrs)
        return "{}({})".format(
            type(self).__name__, ", ".join(map("{}={}".format, attrs, vals))  # type: ignore
        )

    @property
    def target(self) -> int:
        p = self.bits & 0xFFFFFF
        q = (self.bits & 0xFF000000) >> 24
        return p * 2 ** (8 * (q - 3))

    def get_hash_data(self) -> bytes:
        return bytes(self._data)

    @classmethod
    def _fields_types_and_offsets(cls):
        # Typecodes are the codes for the field/attribute type.
        typecodes = ["L", "32s", "32s", "L", "L", "L"]
        # Attributes of the "struct".
        attrs = ["version", "prev_block", "merkle_root", "timestamp", "bits", "nonce"]
        # Offset formats (for calculating offset with struct.calcsize)
        offset_fmts = accumulate(typecodes, concat)
        # Actual attribute offsets
        offsets = prepend(0, map(struct.calcsize, offset_fmts))  # type: ignore
        return dict(zip(attrs, zip(typecodes, offsets)))

    def verify(self) -> bool:
        """Checks if the block header is valid."""
        return bytes_to_int_little(self.hash) < self.target

    @classmethod
    def from_json(cls, filename: str, fields: dict[str, int] | None = None) -> Self:
        """Returns a new BlockHeader instance by parsing a JSON."""
        return cls.from_buffer(parse_block_json(filename, fields))  # type: ignore

    # This was a hack for ensuring that the interface and behaviour remained mostly
    # the same as the previous version of this class. There wasn't any clean fix for this.
    # Essentially, there is an underlying buffer of memory
    # tied to this class, and attributes are actually fetched from raw binary data.

    def __getattr__(self, name: str) -> Any:
        if name == "_data":
            return super().__getattribute__(name)
        try:
            typecode, offset = type(self)._fields_types_and_offsets()[name]
            return struct.unpack_from(typecode, self._data, offset)[0]
        except KeyError:
            raise

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "_data":
            super().__setattr__(name, value)
        else:
            try:
                typecode, offset = type(self)._fields_types_and_offsets()[name]
                struct.pack_into(typecode, self._data, offset, value)
            except KeyError:
                raise

    # This was strictly to keep the interface the same. This method will
    # eventually be removed.
    @classmethod
    def from_buffer(cls, buf: bytes) -> Self:
        """Note that the behaviour of this method has changed.
        The object does not point to teh same area in memory provided
        to this method.
        """
        args = struct.unpack("<L32s32s3L", buf)
        return cls(*args)

    def __bytes__(self) -> bytes:
        return bytes(self._data)

    def _check_nonce(self, nonce: int) -> bool:
        """Checks a nonce to see if a valid hash is produced.
        This modifies the original struct.
        """
        self.nonce = nonce
        return self.verify()


@dataclass
class TxIn(BinaryHashable):
    prev_tx_hash: bytes
    prev_tx_out_index: int
    script: bytes
    sequence: int = 0xFFFFFFFF

    def __bytes__(self) -> bytes:
        return b""


@dataclass
class TxOut(BinaryHashable):
    value: int
    script: bytes

    def __bytes__(self) -> bytes:
        return b""


@dataclass
class Tx(BinaryHashable):
    version: int
    inputs: list[TxIn]
    outputs: list[TxOut]
    lock_time: int

    @property
    def valid(self) -> bool:
        return NotImplemented

    def get_hash_data(self) -> bytes:
        return bytes(self)

    def __bytes__(self) -> bytes:
        ret = bytearray()
        # Add version number as a 4 byte little endian integer.
        ret += struct.pack("<L", self.version)
        # Convert inputs and outputs to raw binary data (varint and data).
        ret += list_to_bytes(self.inputs)
        ret += list_to_bytes(self.outputs)
        # Add locktime as a 4 byte little endian integer.
        ret += struct.pack("<L", self.lock_time)
        return bytes(ret)

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
    def blocksize(self) -> int:  # type: ignore
        return 0

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
