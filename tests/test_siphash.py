import struct

from src.siphash import siphash


def test_siphash() -> None:
    k = struct.pack("<2Q", 0x0706050403020100, 0x0F0E0D0C0B0A0908)
    assert (
        siphash(k, bytes.fromhex("000102030405060708090a0b0c0d0e"))
        == 0xA129CA6149BE45E5
    )
