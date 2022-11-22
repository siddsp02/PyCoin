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
from typing import NamedTuple

from typing_extensions import Self

CURVE = (p, a, b, G, n, h) = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    0x0,
    0x7,
    0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    0x1,
)


# fmt: off

class AffinePoint(NamedTuple):
    x: int
    y: int

    @classmethod
    def infinity(cls) -> Self:
        return cls(None, None) # type: ignore

    @classmethod
    def from_int(cls, value: int) -> Self:
        """Returns a new Point on the secp256k1 curve when given its integer value."""
        bits = value.bit_length()
        length = 33 if bits <= 272 else 65
        val_bytes = value.to_bytes(length, byteorder="big")
        return cls.from_bytes(val_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Returns a new Point on the secp256k1 curve when given binary data.
        In this case, we unpack our data with big-endian as our byte format,
        since that is the network standard.
        """
        prefix, x = struct.unpack("!B32s", data)
        size = len(data)
        x = int.from_bytes(x, byteorder="big")
        # Parse the data depending on the format in which the bytes are stored.
        if prefix in {2, 3} and size == 33:
            curve = (pow(x, 3, p) + b) % p
            y = tonelli(curve, p)
        elif prefix == 4 and size == 65:
            y = struct.unpack_from("!32s", data, offset=33)
            y = int.from_bytes(y, byteorder="big")
        else:
            raise ValueError("Invalid parameters.")
        point = AffinePoint(x, y)  # type: ignore
        if not point.on_curve:
            raise ValueError("Invalid point (bad x coord).")
        # NOTE: This needs to be fixed. Negation has nothing to do with
        # the prefix. The prefix denotes whether the y value should be
        # even or odd, so the solution might be finding the other root
        # modulo p to get the y value of the point from the x coordinate
        # using the Tonelli shanks algorithm.
        return point if prefix != 3 else -point

    @property
    def on_curve(self) -> bool:
        (x, y) = self
        if y is None:
            return False
        return (x*x*x + b) % p == y*y % p

    def __bytes__(self) -> bytes:
        """Returns the bytes of the point in uncompressed form, using SEC Encoding.
        This is the same type of encoding used to parse a point from a bytes object.
        """
        x_bytes = self.x.to_bytes(32, byteorder="big")
        y_bytes = self.y.to_bytes(32, byteorder="big")
        return struct.pack("!B32s32s", 4, x_bytes, y_bytes)

    def __str__(self) -> str:
        return f"{*self,}"

    def __neg__(self) -> Self:
        """Returns the negated value of a Point on the secp256k1 curve.
        The negated value of a point is a point such that the original
        point added to it results in the point at infinity. In the case
        of the elliptic curve, this is just the point with the y-value
        negated.

        Examples:
        >>> p = AffinePoint(x=103, y=427)
        >>> -p
        AffinePoint(x=103, y=-427)
        >>> p = AffinePoint(x=12, y=312)
        >>> -p
        AffinePoint(x=12, y=-312)
        >>> p = AffinePoint(x=327, y=113)
        >>> -p
        AffinePoint(x=327, y=-113)
        """
        (x, y) = self
        return AffinePoint(x, -y)

    def __add__(self, other: Self | tuple[int, int]) -> Self:
        """Returns the result of adding two points on the secp256k1 curve.

        When adding two points, a regular tuple is also considered as a
        point on the curve, meaning that an operation can be performed on
        one as well. This allows us to add a tuple to our Point without
        having to worry about conversions.

        Note that adding a point to its negation results in a Point(0, 0).
        This is also known as the Point at infinity (in this case),
        which is a special value such that adding a Point to it will result
        in the original point. This is also the field/value a on secp256k1.

        Examples:
        >>> p1 = AffinePoint(x=31, y=26)
        >>> p1 + -p1
        AffinePoint(x=None, y=None)
        >>> p1 = AffinePoint(x=216, y=3)
        >>> p2 = AffinePoint(x=216, y=-3)
        >>> p1 + p2
        AffinePoint(x=None, y=None)

        References:
            - https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
        """
        infinity = AffinePoint.infinity()
        (xp, yp), (xq, yq) = self, other
        if self == infinity:
            return other  # type: ignore
        elif self == other:
            m = 3*(xp*xp % p) * pow(2*yp, -1, p)
        elif -self == other:
            return infinity
        else:
            m = (yq-yp) * pow(xq-xp, -1, p) % p
        xr = ((m*m % p) - xp - xq) % p
        yr = (m * (xp-xr) - yp) % p
        return AffinePoint(xr, yr)

    __radd__ = __add__

    def __mul__(self, other: int) -> Self:
        """Elliptic curve multiplication of a point by a scalar value.

        Point multiplication is done by repeatedly doubling and adding
        a point along a curve based on the bits of the scalar value.

        References:
            - https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
        """
        mask, bits = 1, other.bit_length() - 1
        tmp, res = self, AffinePoint.infinity()
        for _ in range(bits + 1):
            if other & mask:
                res += tmp
            tmp += tmp
            mask <<= 1
        return res

    __rmul__ = __mul__  # type: ignore


# By default, Projective/Jacobian coordinates are used to represent points
# since they are much faster for Point arithmetic, due to modular inverse
# calculations being computationally expensive.

# Another benefit to using Projective coordinates over Affine coordinates
# is the point at infinity having a defined representation as a point at
# (0, 1, 0).

class Point(NamedTuple):
    x: int
    y: int
    z: int = 1  # For affine coordinate conversion.
    
    @classmethod
    def infinity(cls) -> Self:
        return cls(0, 1, 0)

    @classmethod
    def from_affine(cls, point: AffinePoint) -> Self:
        return cls(point.x, point.y, 1)

    @classmethod
    def from_int(cls, value: int) -> Self:
        bits = value.bit_length()
        length = 33 if bits <= 272 else 65
        val_bytes = value.to_bytes(length, byteorder="big")
        return cls.from_bytes(val_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        new_point = AffinePoint.from_bytes(data)
        return Point.from_affine(new_point)

    @property
    def on_curve(self) -> bool:
        new_point = self.affine()
        return new_point.on_curve

    def affine(self) -> AffinePoint:
        (x, y, z) = self
        xr = x * pow(z, -2, p) % p
        yr = y * pow(z, -3, p) % p
        return AffinePoint(xr, yr)

    def __str__(self) -> str:
        return f"{*self,}"

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
                return Point(0, 1, 0)
            y_2 = y*y % p
            y_4 = y_2*y_2 % p
            x_2 = x*x % p
            s = 4*x*y_2 % p
            m = (3*x_2) % p
            x3 = (m*m - 2*s) % p
            y3 = (m * (s-x3) - 8*y_4) % p
            z3 = 2*y*z % p
        else:
            (x1, y1, z1) = self
            (x2, y2, z2) = other
            z1_2 = z1*z1 % p
            z2_2 = z2*z2 % p
            u1 = x1*z2_2 % p
            u2 = x2*z1_2 % p
            s1 = y1*z2*z2_2 % p
            s2 = y2*z1*z1_2 % p
            h = (u2-u1) % p
            t = 2*h % p
            i = t*t % p
            j = h*i % p
            r = 2 * (s2-s1) % p
            v = u1*i % p
            x3 = (r*r % p - j - 2*v) % p
            y3 = (r*(v-x3) - 2*s1*j) % p
            zs = (z1+z2) % p
            zs_2 = zs*zs % p
            z3 = (zs_2-z1_2-z2_2) * h % p
        return Point(x3, y3, z3)

    __radd__ = __add__

    def __mul__(self, other: int) -> Self:
        """Elliptic curve multiplication of a point by a scalar value, using
        double-and-add.

        Point multiplication is done by repeatedly doubling and adding a point
        along a curve based on the bits of the scalar value.

        References:
            - https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
        """
        mask, bits = 1, other.bit_length() - 1
        tmp, res = self, Point(0, 1, 0)
        for _ in range(bits + 1):
            if other & mask:
                res += tmp
            tmp += tmp
            mask <<= 1
        return res

    __rmul__ = __mul__  # type: ignore


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
    z = next(
        z for z in range(p) if jacobi(z, p) == -1
    )
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
