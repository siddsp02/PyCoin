import pytest

from src.constants import UINT8_MAX, UINT16_MAX, UINT32_MAX, UINT64_MAX
from src.encoding_schemes.varint import varint


def test_varint() -> None:
    # Test construction as well as bounds checking.
    val = varint(0xFA)
    assert val == 0xFA
    with pytest.raises(ValueError):
        val = varint(0xFFFFFFFFFFFFFFFF1)
    with pytest.raises(ValueError):
        val = varint(-9)
    val = varint(0xFEFA)
    assert val == 0xFEFA


def test_varint_decoding() -> None:
    # Values smaller than 0xFD should have the same value.
    val = bytes([0x9])
    assert varint.from_bytes(val) == 0x9
    val = bytes([0xFD, 0xFA, 0xFF])
    # Order should be reversed since values are encoded in little-endian.
    # We can verify this by testing all sorts of valid inputs.
    assert varint.from_bytes(val) == 0xFFFA
    val = bytes([0xFE, 0xFF, 0xFA, 0xAB, 0x1A])
    assert varint.from_bytes(val) == 0x1AABFAFF


def test_varint_encoding() -> None:
    val = varint(0xFFFA)
    assert bytes(val) == bytes([0xFD, 0xFA, 0xFF])
    val = varint(0x1AABFAFF)
    assert bytes(val) == bytes([0xFE, 0xFF, 0xFA, 0xAB, 0x1A])
    # Test integer boundary values.
    val = varint(UINT64_MAX)
    assert bytes(val) == bytes([0xFF] * 9)
    val = varint(UINT32_MAX)
    assert bytes(val) == bytes([0xFE] + [0xFF] * 4)
    val = varint(UINT16_MAX)
    assert bytes(val) == bytes([0xFD] + [0xFF] * 2)
    val = varint(UINT8_MAX)
    assert bytes(val) == bytes([0xFD, 0xFF, 0x00])
    val = varint(0xFD)
    assert bytes(val) == bytes([0xFD, 0xFD, 0x00])
