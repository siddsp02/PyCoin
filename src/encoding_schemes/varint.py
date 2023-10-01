"""Varint integer type for network protocol.
Also known as CompactSize in Bitcoin Core.
"""

import struct
from typing import Self
from src.constants import UINT64_MAX
from src.utils import int_to_varint


class varint(int):
    def __new__(cls, *args, **kwargs) -> Self:
        value = int(*args, **kwargs)
        if value < 0:
            raise ValueError("Value must be greater than 0 (unsigned).")
        if value > UINT64_MAX:
            raise ValueError("Values can only be at most 8 bytes long.")
        return super().__new__(cls, value)

    __bytes__ = int_to_varint

    @classmethod
    def from_bytes(cls, buf: bytes) -> Self:
        """Returns a varint based on the prefix of the first byte of the buffer.

        If the buffer is longer than needed, only the amount of bytes denoted
        by the prefix of the buffer is taken and converted to a varint.

        References:
            - https://en.bitcoin.it/wiki/Protocol_documentation  (See Variable Length Integer)
        """
        res = buf[0]
        match res:
            case 0xFD:
                res = struct.unpack_from("<H", buf, offset=1)[0]
            case 0xFE:
                res = struct.unpack_from("<L", buf, offset=1)[0]
            case 0xFF:
                res = struct.unpack_from("<Q", buf, offset=1)[0]
        return cls(res)
