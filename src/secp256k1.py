# !usr/bin/env python3


"""Secp256k1 elliptic curve cryptography for Bitcoin.
Operator overloading allows Points to be used as a one-to-one
representation of their mathematical equivalent.

Note that this module is not secure even when using secrets
for random number generation since point addition and
multiplication use methods that are vulnerable to
timing attacks, so don't use this for encryption or security
purposes.
"""

from __future__ import annotations

import struct
from typing import NamedTuple, Self

try:
    from .utils import bits, int_to_bytes_big, modinv
except ImportError:
    from utils import bits, int_to_bytes_big, modinv

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0x0
B = 0x7
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
H = 0x1

INFINITY = (0, 1, 0)  # Coordinates for point at infinity.

# fmt: off

class Point(NamedTuple):
    """Represents a point on an Elliptic Curve using projective coordinates."""
    
    x: int
    y: int
    z: int = 1  # For affine coordinate conversion.

    @classmethod
    def from_int(cls, value: int) -> Self:
        bits = value.bit_length()
        length = 33 if bits <= 272 else 65
        val_bytes = value.to_bytes(length, byteorder="big")
        return cls.from_bytes(val_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        pref, xbin = struct.unpack(">B32s", data)
        x = int.from_bytes(xbin, byteorder="big")
        if pref in {0x2, 0x3} and len(data) == 33:
            curve = (x*x*x + B) % P
            y = tonelli(curve, P)
            if y is None:
                raise ValueError("Invalid point (bad x coord).")
        elif pref == 0x4 and len(data) == 65:
            ybin = struct.unpack_from(">32s", data, offset=33)
            y = int.from_bytes(ybin, byteorder="big")
        else:
            raise ValueError("Invalid parameters.")
        point = cls(x, y)
        if not point.on_curve:
            raise ValueError("Invalid point (bad x coord).")
        return point

    def affine(self) -> tuple[int, int]:
        (x, y, z) = self
        zi = modinv(z, P)
        zi_2 = zi*zi % P
        zi_3 = zi*zi_2 % P
        x, y = x*zi_2 % P, y*zi_3 % P 
        return (x, y)

    @property
    def on_curve(self) -> bool:
        x, y = self.affine()
        x_3 = x*x*x % P
        return (x_3 + B) % P == y*y % P

    def double(self) -> Self:
        (x, y, z) = self
        if y == 0:
            return type(self)(0, 1, 0)
        y_2 = y*y % P
        y_4 = y_2*y_2 % P
        x_2 = x*x % P
        s = 4*x*y_2 % P
        m = (3*x_2) % P
        x3 = (m*m - 2*s) % P
        y3 = (m * (s-x3) - 8*y_4) % P
        z3 = 2*y*z % P
        return type(self)(x3, y3, z3)
        

    def __str__(self) -> str:
        return f"{*self,}"

    def __bytes__(self) -> bytes:
        # When converted to binary, uncompressed format is assumed.
        x, y = self.affine()
        return struct.pack(">B32s32s", 0x4, int_to_bytes_big(x), int_to_bytes_big(y))

    def __add__(self, other: Self) -> Self:
        """Addition of two projective/jacobian coordinate points using "add-2007-bl"
        algorithm. The code for point doubling was borrowed from the Bitcoin Core
        repository, as well as the WikiBooks reference.

        Currently, Point addition is the bottleneck when it comes to signature
        verification speed. This is likely due to multiprecision arithmetic in
        Python overall being unoptimized. GMP tends to be much faster, and can
        be configured using the gmpy library for Python. In this case, I wanted
        as few external dependencies as possible, so I stuck to the standard
        library.
        
        References:
            - https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html
            - https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
            - https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
            - https://github.com/bitcoin/bitcoin/tree/master/test/functional
        """
        if self == (0, 1, 0):  # Point at infinity.
            return other
        if self == other:
            (x, y, z) = self
            if y == 0:
                return type(self)(0, 1, 0)
            y_2 = y*y % P
            y_4 = y_2*y_2 % P
            x_2 = x*x % P
            s = 4*x*y_2 % P
            m = (3*x_2) % P
            x3 = (m*m - 2*s) % P
            y3 = (m * (s-x3) - 8*y_4) % P
            z3 = 2*y*z % P
        else:
            (x1, y1, z1) = self
            (x2, y2, z2) = other
            z1_2 = z1*z1 % P
            z2_2 = z2*z2 % P
            u1 = x1*z2_2 % P
            u2 = x2*z1_2 % P
            s1 = y1*z2*z2_2 % P
            s2 = y2*z1*z1_2 % P
            h = (u2-u1) % P
            t = 2*h % P
            i = t*t % P
            j = h*i % P
            r = 2 * (s2-s1) % P
            v = u1*i % P
            x3 = (r*r % P - j - 2*v) % P
            y3 = (r*(v-x3) - 2*s1*j) % P
            zs = (z1+z2) % P
            zs_2 = zs*zs % P
            z3 = (zs_2-z1_2-z2_2) * h % P
        return type(self)(x3, y3, z3)

    __radd__ = __add__

    def __mul__(self, other: int) -> Self:
        """Elliptic curve multiplication of a point by a scalar value, using
        double-and-add.

        Point multiplication is done by repeatedly doubling and adding a point
        along a curve based on the bits of the scalar value.

        References:
            - https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
        """
        tmp, res = self, type(self)(0, 1, 0)
        for bit in bits(other, reverse=True):
            if bit:
                res += tmp
            tmp = tmp.double()
        return res

    def __rmul__(self, other: int) -> Self:
        return self * other


def jacobi(n: int, k: int) -> int:
    """Calculate the jacobi symbol of n and k, where k is an odd integer.

    References:
        - https://en.wikipedia.org/wiki/Jacobi_symbol
    """
    assert k > 0 and k & 1
    n, t = n % k, 1
    while n != 0:
        while n % 2 == 0:
            n, r = n >> 1, k % 8
            if r == 3 or r == 5:
                t = -t
        n, k = k, n
        if n % 4 == 3 and k % 4 == 3:
            t = -t
        n %= k
    return t if k == 1 else 0

# When finished, assertions can be removed by instructing -o to the
# compiler, so there will be no overhead to running the algorithm.

def tonelli(n: int, p: int) -> int | None:
    """Returns the value r such that r*r % p == n % p, where p is an odd prime.

    The code below was partially borrowed from the third reference link,
    with some modifications. Namely, instead of using the legendre symbol
    for checking for quadratic non-residues (see variable z and source),
    the jacobi symbol was used instead to check for a value of -1 since
    no number with a jacobi symbol of -1 is a quadratic residue.

    Examples:
    >>> tonelli(44402, 100049)
    30468
    >>> tonelli(10, 13)
    7
    >>> tonelli(56, 101)
    37
    >>> tonelli(1030, 10009)
    1632

    References:
        - https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
        - https://en.wikipedia.org/wiki/Jacobi_symbol
        - https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#Python
    """
    if jacobi(n, p) != 1:
        return None
    # Find the pair q and s such that p - 1 == q * 2**s % p.
    q, s = p - 1, 0
    while q % 2 == 0:
        q, s = q >> 1, s + 1
    z = next(z for z in range(p) if jacobi(z, p) == -1)
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q+1) // 2, p)
    while t != 0 and t != 1:
        # Congruence checks to verify the loop invariant (see references).
        assert (
            pow(c, 1 << (m-1), p) == -1 % p
            and pow(t, 1 << (m-1), p) == 1 % p
            and r*r % p == t*n % p 
        )
        # Getting the value of i can be sped up by repeatedly squaring
        # t**2 % p until the value of i is found such that 0 < i < m,
        # and t**(2**i) % p == 1.
        i = next(i for i in range(m) if pow(t, 1 << i, p) == 1)
        b = pow(c, 1 << (m-i-1), p)
        b2 = b*b % p
        m, c, t, r = i, b2, t*b2 % p, r*b % p
    return r if t == 1 else 0


G = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
