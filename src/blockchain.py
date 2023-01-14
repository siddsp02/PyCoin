"""Blockchain related datatypes (includes transactions and blocks)."""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from functools import cached_property
from typing import NamedTuple, TypeVar

try:
    from .ecdsa import encode
    from .miner import difficulty
    from .merkle import hash_tree
    from .utils import sha256d
except ImportError:
    from ecdsa import encode
    from miner import difficulty
    from merkle import hash_tree
    from utils import sha256d

_T = TypeVar("_T")


# Dataclasses could be used here, but for the purpose of having more
# fine-grained control over behaviour, they have been avoided.


class SigScript:
    """Signature script. Consists of a DER encoded signature as well as
    the corresponding public key.

    References:
        - https://developer.bitcoin.org/reference/transactions.html
    """

    def __init__(self, signature: tuple[int, int], pubkey: bytes) -> None:
        self.signature = encode(signature)  # Signatures are encoded using DER encoding.
        self.pubkey = pubkey

    def __repr__(self) -> str:
        signature, pubkey = self.signature, self.pubkey
        return f"{self.__class__.__name__}({signature=}, {pubkey=})"

    def __bytes__(self) -> bytes:
        return self.signature + self.pubkey

    def size(self) -> int:
        return len(self.signature) + len(self.pubkey)


class OutPoint(NamedTuple):
    tx_out_hash: bytes
    tx_out_index: int

    def __bytes__(self) -> bytes:
        return struct.pack("<32sI", self.tx_out_hash, self.tx_out_index)

    def size(self) -> int:
        return 36


class TxIn(NamedTuple):
    """Transaction input."""

    previous_output: OutPoint
    script: SigScript
    sequence: int = 0xFFFFFFFF

    def __bytes__(self) -> bytes:
        out_size = self.previous_output.size()
        script_size = self.script.size()
        return struct.pack(
            f"<{out_size}s{script_size}sI",
            bytes(self.previous_output),
            bytes(self.script),
            self.sequence,
        )

    def size(self) -> int:
        return self.previous_output.size() + self.script.size() + 4


class TxOut(NamedTuple):
    """Standard transaction output."""

    value: int
    pubkey_script: bytes

    def __bytes__(self) -> bytes:
        script_size = len(self.pubkey_script)
        return struct.pack(f"<I{script_size}s", self.value, self.pubkey_script)

    def size(self) -> int:
        return 4 + len(self.pubkey_script)

    def hash(self, hex: bool = False) -> bytes:
        return b""


@dataclass
class Tx:
    """A transaction on the Bitcoin network.

    References:
        - https://developer.bitcoin.org/reference/transactions.html
        - https://en.bitcoin.it/wiki/Transaction
    """

    version: int = 0x1
    inputs: list[TxIn] = field(default_factory=list)
    outputs: list[TxOut] = field(default_factory=list)
    lock_time: int = 0x00000000  # also known as nLockTime

    def __bytes__(self) -> bytes:
        input_bytes = map(bytes, self.inputs)
        output_bytes = map(bytes, self.outputs)
        input_raw = b"".join(input_bytes)
        output_raw = b"".join(output_bytes)
        return struct.pack(
            f"!Ln{self.input_count}sn{self.output_count}sL",
            self.version,
            self.input_count,
            input_raw,
            self.output_count,
            output_raw,
            self.lock_time,
        )

    @property
    def input_count(self) -> int:
        return len(self.inputs)

    @property
    def output_count(self) -> int:
        return len(self.outputs)

    @property
    def valid(self) -> bool:
        """True if the transaction is valid. False otherwise."""
        ...

    def coindays_destroyed(self) -> Decimal:
        """A way of measuring the economic activity of a transaction,
        which is calculated using proof-of-stake (not for consensus).
        """
        ...

    def confirmations(self) -> int:
        """The number of confirmations for a given transaction."""
        ...

    def size(self) -> int:
        return struct.calcsize(f"!LL{self.input_count}sL{self.output_count}sL")

    def hash(self, hex: bool = False) -> bytes:
        ...


class BlockHeader(NamedTuple):
    """An 80-byte Bitcoin Block Header."""

    version: int
    previous_block: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int

    @classmethod
    def from_bytes(cls, value: bytes) -> BlockHeader:
        data = struct.unpack("<I32s32s3I", value)
        return cls._make(data)

    def __bytes__(self) -> bytes:
        # Bytes are packed in little-endian byteorder.
        return struct.pack("<I32s32s3I", *self)

    def hash(self, hex: bool = False) -> bytes:
        return sha256d(bytes(self))

    def size(self) -> int:
        return 80


class Block:
    def __init__(
        self,
        version: int = 0x1,
        header: BlockHeader | None = None,
        previous_block: Block | None = None,
        txs: list[Tx] | None = None,
    ) -> None:
        # Insertion order is preserved for hash tables, so the hash to tx
        # mapping can be used for proofs of inclusion later on when needed.
        self.txs = {} if txs is None else {tx.hash(): tx for tx in txs}
        self.version = version
        self.previous_block = previous_block
        # To be added later on for adjustment.
        self.header = header  # type: ignore
        self.next_block: Block = None  # type: ignore

    def __repr__(self) -> str:
        version, previous_block, txs = self.version, self.previous_block, self.txs
        return f"{self.__class__.__name__}({version=}, {previous_block=}, {txs=})"

    def __str__(self) -> str:
        ...

    @cached_property  # Allow for faster calculation of block height.
    def height(self) -> int:
        if self.previous_block is None:
            return 0
        return 1 + self.previous_block.height

    @property
    def difficulty(self) -> float:
        if self.height == 0:
            return 1.0
        if self.header is None:
            adjustment_height = 0
        return difficulty(self.header.bits)  # type: ignore

    @property
    def confirmations(self) -> int:
        next_block = self.next_block
        return 1

    def construct_header(self) -> None:
        version = 0x1
        if self.previous_block is None:
            previous_block = bytes(80)
        else:
            previous_block = self.previous_block.hash()
        merkle_root = self.merkle_root()
        utc_time = datetime.utcnow().timestamp()
        timestamp = int(utc_time)
        bits = 0x1
        nonce = 0x1
        self.header = BlockHeader(
            version, previous_block, merkle_root, timestamp, bits, nonce
        )

    def mine(self) -> None:
        self.bits = 0x1
        self.nonce = 0x1

    def merkle_root(self) -> bytes:
        return hash_tree(self.txs)

    def tx_count(self) -> int:
        return len(self.txs)

    def fully_confirmed(self) -> bool:
        return True if self.confirmations > 6 else False

    def get(self, hash: bytes) -> Tx | None:
        return self.txs.get(hash)

    def __getitem__(self, hash: bytes) -> Tx:
        return self.txs[hash]

    def __contains__(self, tx: Tx) -> bool:
        return tx.hash() in self.txs

    def size(self) -> int:
        """Returns the size of the block (in bytes)"""
        return sum(tx.size() for tx in self.txs.values()) + 80

    def hash(self, hex: bool = False) -> bytes:
        ...

    def work_done(self, cumulative: bool = False) -> int:
        """Returns the total work done by the block, if the cumulative keyword
        is specified as 'True', the total work done by the chain is returned.
        """
        ...

    def add_tx(self, tx: Tx) -> None:
        self.txs[tx.hash()] = tx

    def update_txs(self, *txs: Tx) -> None:
        ...

    def update_difficulty(self) -> None:
        ...


def projected_difficulty() -> int:
    """Bitcoin Difficulty Adjustment Algorithm.

    Works by calculating the simple moving average of the last 2016 blocks,
    and adjusting the difficulty based on the average solve time.
    """
    floor_diff = 1
    return 1


if __name__ == "__main__":
    ...
