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
from datetime import datetime
from functools import partial, singledispatch

try:
    from .utils import sha256d
except ImportError:
    from utils import sha256d

UINT32_MAX = 0xFFFFFFFF
WORKERS = mp.cpu_count()


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


def update_timestamp(block_header: bytearray) -> None:
    """Updates the timestamp of a block header."""
    timestamp = datetime.utcnow()
    struct.pack_into("<I", block_header, 68, timestamp)


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


def check_nonce(block: bytearray, nonce: int) -> bool:
    struct.pack_into("<I", block, 76, nonce)  # Update the nonce.
    return verify(block)


if __name__ == "__main__":
    # This is just an example of mining the genesis block.
    # Mining works, but it is slow since looping in Python
    # is expensive. Later on, this might be changed into
    # a C++ extension to speed up looping. The GIL also
    # makes this less than ideal since the overhead for
    # running a process is much more than that of running
    # a thread.
    block = parse_block_json("example_blocks/genesis.json")
    start = 2_080_000_000
    iterations = 2_083_236_893 - start
    check_block = partial(check_nonce, block)
    t1 = time.perf_counter()
    with mp.Pool(processes=WORKERS) as pool:
        results = pool.imap(
            check_block,
            range(start, UINT32_MAX),
            chunksize=20_000,
        )
        for result in filter(None, results):
            break
        else:
            print("Nonce not found.")
    t2 = time.perf_counter()
    print(f"Done {iterations=} in {t2-t1:.8f} seconds")
    print(f"Hashrate was ~{iterations//(t2-t1)} H/s")
