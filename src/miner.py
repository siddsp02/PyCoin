# !usr/bin/env python3

"""The miner for Bitcoin. Works by guessing a nonce for the
block header, and then checking if the hash is less than the
target amount.

Transaction validation and full blocks will be added later on,
along with merkle tree hashing, difficulty adjustment, and
timestamp updates -- the whole thing.
"""

import json
import multiprocessing as mp
import struct
import time
from datetime import datetime
from functools import partial, singledispatch

from header import target, verify

UINT32_MAX = 0xFFFFFFFF
WORKERS = mp.cpu_count()


def update_timestamp(block_header: bytearray) -> None:
    """Updates the timestamp of a block header."""
    timestamp = datetime.utcnow()
    struct.pack_into("<I", block_header, 3, timestamp)


def get_target(block_header: bytearray) -> int:
    bits = struct.unpack_from("<I", block_header, 72)[0]
    return target(bits)


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
        value = bytes.fromhex(value)[::-1]  # type: ignore
        struct.pack_into("<32s", header, offset, value)

    @pack_bytes.register
    def _(value: int, offset: int = 0) -> None:
        struct.pack_into("<I", header, offset, value)

    # Parse JSON fields, and pack the values
    # into the bytearray of the block header.
    with open(filename) as f:
        block = json.load(f, object_pairs_hook=list)
        for key, value in block:
            if key in fields:
                pack_bytes(value, fields[key])

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
