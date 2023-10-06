"""Varint integer type for network protocol.
Also known as CompactSize in Bitcoin Core.

References:
    - https://en.bitcoin.it/wiki/Protocol_documentation  (See Variable Length Integer)
"""

from io import BytesIO
from typing import Self
from src.constants import UINT64_MAX
from src.utils import bytes_to_int_little, int_to_varint


class varint(int):
    def __new__(cls, *args, **kwargs) -> Self:
        value = int(*args, **kwargs)
        if value < 0:
            raise ValueError("Value must be non-negative.")
        if value > UINT64_MAX:
            raise ValueError("Values can only be at most 8 bytes long.")
        return super().__new__(cls, value)

    __bytes__ = int_to_varint

    @classmethod
    def read(cls, value: int) -> bytes:
        """Returns the binary value of an integer using varint encoding.

        This is used to avoid the pattern of having to write bytes(varint(value)),
        since varint.read(value) can be used instead.
        """
        return bytes(cls(value))

    @staticmethod
    def get_size(prefix: int) -> int:
        """Returns the size of a varint given its prefixed encoding."""
        return {0xFD: 2, 0xFE: 4, 0xFF: 8}.get(prefix, 1)

    @classmethod
    def from_bytes(cls, buf: bytes) -> Self:  # type: ignore
        """Returns a varint based on the prefix of the first byte of the buffer.

        If the buffer is longer than needed, only the amount of bytes denoted
        by the prefix of the buffer is taken and converted to a varint.
        """
        n = cls.get_size(buf[0])
        res = bytes_to_int_little(buf[1 : 1 + n]) if n > 1 else buf[0]
        return cls(res)

    @classmethod
    def from_stream(cls, stream: BytesIO) -> Self:
        """Returns a varint based on the prefix of the first byte of the stream.

        Note that this moves the cursor of the stream, which can change what
        values are supposed to be read next for the caller.
        """
        first = stream.read(1)[0]
        n = cls.get_size(first)
        res = bytes_to_int_little(stream.read(n)) if n > 1 else first
        return cls(res)
