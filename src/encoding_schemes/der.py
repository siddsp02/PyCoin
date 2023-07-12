import struct

from ..utils import bytes_to_int_big, int_to_bytes_big


def encode(sig: tuple[int, int]) -> bytes:
    """Returns a DER signature when given a signature pair (r, s).

    References:
        - https://bitcoin.stackexchange.com/questions/12554/
    """
    (r, s) = map(int_to_bytes_big, sig)
    if r[0] > 0x7F:
        r = b"\x00" + r
    if s[0] > 0x7F:
        s = b"\x00" + s
    rlen, slen = len(r), len(s)
    size = 1 + 2 + rlen + 2 + slen
    fmt = f">4B{rlen}s2B{slen}s"
    return struct.pack(fmt, 0x30, size - 1, 0x2, rlen, r, 0x2, slen, s)


def decode(sig: bytes) -> tuple[int, int]:
    """Returns the decoded signature pair of a DER-encoded signature.

    References:
        - https://bitcoin.stackexchange.com/questions/12554/
    """
    rlen = sig[3]
    offset = 4
    r = bytes_to_int_big(sig[offset : offset + rlen])
    offset += rlen + 1
    slen = sig[offset]
    offset += 1
    s = bytes_to_int_big(sig[offset : offset + slen])
    return (r, s)


def decode_hex(sig: str) -> tuple[int, int]:
    """Returns the decoded signature pair of a DER-encoded signature
    when given a hex string.
    """
    return decode(bytes.fromhex(sig))
