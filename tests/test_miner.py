from itertools import repeat
import random
import math

from src.blockchain.miner import *


def test_verify() -> None:
    # Block 125552
    buf = bytearray.fromhex(
        "01000000"
        + "81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"
        + "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"
        + "c7f5d74d"
        + "f2b9441a"
        + "42a14695"
    )
    blk = BlockHeader.from_buffer(buf)
    assert blk.verify()
    buf[20] += 1
    assert not blk.verify()


def test_parse_block_json() -> None:
    blk = parse_block_json("example_blocks/125552.json")
    assert blk == bytes.fromhex(
        "01000000"
        + "81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"
        + "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"
        + "c7f5d74d"
        + "f2b9441a"
        + "42a14695"
    )


def test_difficulty() -> None:
    assert difficulty(0x1B0404CB) == 16307.420938523983


def test_target() -> None:
    assert (
        target(0x1B0404CB)
        == 0x00000000000404CB000000000000000000000000000000000000000000000000
    )


def test_hashrate_from_difficulty() -> None:
    hashrate = hashrate_from_difficulty(3.41e13)
    assert math.isclose(hashrate, 2.68e20, rel_tol=0.25)


def test_get_target() -> None:
    block = bytes.fromhex(
        "01000000"
        + "81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"
        + "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"
        + "c7f5d74d"
        + "f2b9441a"
        + "42a14695"
    )


def test_check_nonce() -> None:
    buf = bytearray.fromhex(
        "01000000"
        + "81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"
        + "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"
        + "c7f5d74d"
        + "f2b9441a"
        + "42a14695"
    )
    block = BlockHeader.from_buffer(buf)
    # Check a large, but limited range of values.
    for i in range(2_504_400_000, 2_504_445_000):
        val = block._check_nonce(i)
        assert val if i == 2504433986 else not val
