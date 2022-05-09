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
import doctest

import multiprocessing as mp
import random
import struct
import time
from typing import NamedTuple

from .utils import bytelength, extract_bits, sha256d

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
    def infinity(cls) -> AffinePoint:
        return AffinePoint(None, None) # type: ignore

    @classmethod
    def from_int(cls, value: int) -> AffinePoint:
        """Returns a new Point on the secp256k1 curve when given its integer value."""
        bits = value.bit_length()
        length = 33 if bits <= 272 else 65
        val_bytes = value.to_bytes(length, byteorder="big")
        return cls.from_bytes(val_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> AffinePoint:
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
        return (pow(x, 3, p) + b) % p == pow(y, 2, p)

    def __bytes__(self) -> bytes:
        """Returns the bytes of the point in uncompressed form, using SEC Encoding.
        This is the same type of encoding used to parse a point from a bytes object.
        """
        x_bytes = self.x.to_bytes(32, byteorder="big")
        y_bytes = self.y.to_bytes(32, byteorder="big")
        return struct.pack("!B32s32s", 4, x_bytes, y_bytes)

    def __str__(self) -> str:
        return f"{*self,}"

    def __neg__(self) -> AffinePoint:
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

    def __add__(self, other: AffinePoint | tuple[int, int]) -> AffinePoint:
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

    def __mul__(self, other: int) -> AffinePoint:
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
    def infinity(cls) -> Point:
        return Point(0, 1, 0)

    @classmethod
    def from_affine(cls, point: AffinePoint) -> Point:
        return cls(point.x, point.y, 1)

    @classmethod
    def from_int(cls, value: int) -> Point:
        bits = value.bit_length()
        length = 33 if bits <= 272 else 65
        val_bytes = value.to_bytes(length, byteorder="big")
        return cls.from_bytes(val_bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> Point:
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

    def __add__(self, other: Point) -> Point:
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
                return Point.infinity()
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

    def __mul__(self, other: int) -> Point:
        """Elliptic curve multiplication of a point by a scalar value, using
        double-and-add.

        Point multiplication is done by repeatedly doubling and adding a point
        along a curve based on the bits of the scalar value.

        Since the dominating factor of point multiplication is point addition,
        multiplication by a scalar can be sped up by using wNAF (Non Adjacent Form)
        for a 50% speed up asymptotically. In practice, trying to extract the NAF
        of an integer has quite a lot of overhead in Python.

        References:
            - https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
        """
        mask, bits = 1, other.bit_length() - 1
        tmp, res = self, Point.infinity()
        for _ in range(bits + 1):
            if other & mask:
                res += tmp
            tmp += tmp
            mask <<= 1
        return res

    __rmul__ = __mul__  # type: ignore

# fmt: off

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


# fmt: off

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
        b2 = pow(b, 2, p)
        m, c, t, r = i, b2, t*b2 % p, r*b % p
    return r if t == 1 else 0

G = Point.from_int(G)

def generate(privkey: int, message: bytes = b"") -> tuple[int, int]:
    """Signs a message when given a private key, returning the signature of
    the signed message in the form of a an integer pair (r, s).

    References:
        - https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    """
    message_hash = sha256d(message)
    z = extract_bits(message_hash, start=0, end=256)
    (r, s) = (0, 0)  # Start with invalid values by default.
    while r == 0 or s == 0:
        k = random.randrange(1, n)
        (x, y) = (k * G).affine()  # type: ignore
        r = x % n
        s = pow(k, -1, n) * (z + r * privkey) % n
    return (r, s)


def verify(signature: tuple[int, int], pubkey: Point, message: bytes) -> bool:
    """Verifies that the message given was signed by the given public key.

    References:
        - https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    """
    if not pubkey.on_curve or pubkey == (0, 1, 0):
        return False
    message_hash = sha256d(message)
    z = extract_bits(message_hash, start=0, end=256)
    (r, s) = signature
    s1 = pow(s, -1, n)
    u1, u2 = (z * s1) % n, (r * s1) % n
    (x, y, z) = point = u1 * G + u2 * pubkey
    if point == (0, 1, 0):
        return False
    (x, y) = point.affine()  # type: ignore
    return r == x % n


def encode(signature: tuple[int, int]) -> bytes:
    """Returns a DER signature when given a signature pair (r, s).

    References:
        - https://bitcoin.stackexchange.com/questions/12554/
    """
    (r, s) = signature
    r_size, s_size = bytelength(r), bytelength(s)
    r_prefix, *r = r.to_bytes(r_size, byteorder="big")
    s_prefix, *s = s.to_bytes(s_size, byteorder="big")
    r, s = bytes(r), bytes(s)
    # Formatted strings for packing the byte values of the signature.
    r_fmt, s_fmt = f"B{r_size-1}s", f"B{s_size-1}s"
    # If the most significant byte of r and s are greater than 0x7F,
    # values are left-padded with the pad byte 0x00 by convention.
    if r_prefix > 0x7F:
        r_fmt = "!x" + r_fmt
    if s_prefix > 0x7F:
        s_fmt = "!x" + s_fmt
    # Re-pack our signature bytes based on the new format string.
    r = struct.pack(r_fmt, r_prefix, r)
    s = struct.pack(s_fmt, s_prefix, s)
    r_size, s_size = len(r), len(s)
    # For the 1st byte (0-based-indexing) of our message, the value
    # is the length of the remaining data used in the DER signature.
    ec_size = 1 + r_size + 2 + s_size + 1
    sig_fmt = f"!4B{r_size}s2B{s_size}sB"
    sighash = 0x00  # This needs to be assigned.
    return struct.pack(
        sig_fmt, 0x30, ec_size, 0x02, r_size, r, 0x02, s_size, s, sighash
    )


def decode(signature: bytes) -> tuple[int, int]:
    """Returns the decoded signature pair of a DER-encoded signature.

    References:
        - https://bitcoin.stackexchange.com/questions/12554/
    """
    header, ec_size = struct.unpack_from("!2B", signature)
    if ec_size != len(signature) - 3:
        raise ValueError("Signature has invalid encoding length.")
    if header != 0x30:
        raise ValueError("Signature does not have proper header prefix.")
    int_flag, r_size = struct.unpack_from("!2B", signature, offset=2)
    if int_flag != 0x02:
        raise ValueError("Signature not properly encoded.")
    r, int_flag, s_size = struct.unpack_from(f"!{r_size}sBB", signature, offset=4)
    if int_flag != 0x02:
        raise ValueError("Signature not properly encoded.")
    s, sighash = struct.unpack_from(f"!{s_size}sB", signature, offset=4 + r_size + 2)
    assert sighash == 0x00  # TODO: Change valid sighash value.
    r = int.from_bytes(r, byteorder="big")
    s = int.from_bytes(s, byteorder="big")
    return (r, s)


def generate_sigs(amount: int) -> list:
    cores = mp.cpu_count()
    msgs = [random.randbytes(10)] * amount
    keys = [random.randrange(1, n)] * amount
    pubkeys = [k * G for k in keys]
    with mp.Pool() as pool:
        sigs = pool.starmap(generate, zip(keys, msgs), chunksize=amount // cores)
    return list(zip(sigs, pubkeys, msgs))


def verify_sigs(params: list) -> list:
    cores = mp.cpu_count()
    amount = len(params)
    with mp.Pool() as pool:
        results = pool.starmap(verify, params, chunksize=amount // cores)
    return results

# fmt: on

# Signature verification is likely to be slow due to
# the inherent lack of speed for multiprecision math.
# On my 8 core machine, I was able to increase signature
# verification rate from ~50/s to ~2,000/s using Projective
# coordinates instead of affine coordinates, as well as
# parallel processing.
# With GMP, you can expect a speedup by at least an order
# of magnitude, so somewhere in the thousands of transactions
# per second range on a single core.

if __name__ == "__main__":
    # Check that things are working as intended.
    doctest.testmod()
    # A small signature verification benchmark.
    amount = 10_000
    s = time.perf_counter()
    sigs = generate_sigs(amount)
    e = time.perf_counter()
    print(e - s)
    s = time.perf_counter()
    verified = verify_sigs(sigs)
    e = time.perf_counter()
    print(amount / (e - s))
    print(all(verified))
