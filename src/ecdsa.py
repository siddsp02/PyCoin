# !usr/bin/env python3

import base64
import multiprocessing as mp
import random
import struct
from itertools import repeat
from typing import Iterable, NamedTuple, Self

try:
    from . import der
    from .constants import WORKERS
    from .secp256k1 import INFINITY, G, N, P, Point
    from .utils import extract_bits, int_to_bytes_big, modinv, sha256d
except ImportError:
    import der
    from constants import WORKERS
    from secp256k1 import INFINITY, G, N, P, Point
    from utils import extract_bits, int_to_bytes_big, modinv, sha256d


random.seed(1)

# fmt: off

class Signature(NamedTuple):
    r: int
    s: int
    
    def base64(self, pubkey: Point) -> bytes:
        x, y = pubkey.affine()
        r, s = self
        if r < P-N:
            header_byte = 0x30 if y % 2 == 0 else 0x27
        else:
            header_byte = 0x28 if y % 2 == 0 else 0x29
        sigbin = struct.pack(">B32s32s", header_byte, int_to_bytes_big(r), int_to_bytes_big(s))
        return base64.encodebytes(sigbin)
    
    @classmethod
    def generate(cls, key: int, msg: bytes = b"") -> Self:
        z = extract_bits(sha256d(msg), start=0, end=256)
        r = s = 0  # Start with invalid values by default.
        while r == 0 or s == 0:
            k = random.randint(1, N-1)
            x, _ = (k*G).affine()
            r = x % N
            s = modinv(k, N) * (z + r*key) % N
        return cls(r, s)
    
    def verify(self, pubkey: Point, msg: bytes) -> bool:
        if not pubkey.on_curve or pubkey == INFINITY:
            return False
        z = extract_bits(sha256d(msg), start=0, end=256)
        r, s = self
        s1 = modinv(s, N)
        u1, u2 = z*s1 % N, r*s1 % N
        point = u1*G + u2*pubkey
        x, y = point.affine()
        return r == x % N
    
    @classmethod
    def decode(cls, sig: bytes) -> Self:
        """Decodes a DER encoded signature. """
        return cls._make(der.decode(sig))

    @classmethod
    def generate_many(
        cls, amount: int, msgs: Iterable[bytes] | None = None
    ) -> Iterable[tuple[Self, Point, bytes]]:
        if msgs is None:
            msgs = repeat(random.randbytes(10), amount)
        keys = (random.randint(1, N-1) for _ in range(amount))
        pubkeys = (k*G for k in keys)
        chunksize = amount // WORKERS
        with mp.Pool() as pool:
            sigs = pool.starmap(cls.generate, zip(keys, msgs), chunksize)
        return zip(sigs, pubkeys, msgs)

    @classmethod
    def verify_all(
        cls, params: Iterable[tuple[Self, Point, bytes]], chunksize: int = 1
    ) -> bool:
        if chunksize <= 0:
            raise ValueError(
                f"chunksize must be positive. Got a value of {chunksize} instead."
            )
        with mp.Pool() as pool:
            results = pool.starmap(cls.verify, params, chunksize)
        return all(results)

    def encode(self) -> bytes:
        """Encodes a signature using DER encoding."""
        return der.encode(self)
