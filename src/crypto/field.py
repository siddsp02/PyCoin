"""Finite field (integers modulo some prime p) elements in math."""

from __future__ import annotations
from functools import cache

import random

from dataclasses import dataclass
from typing import Self

from src.crypto.secp256k1 import tonelli
from src.utils import modinv


# This function will probably be cached because it is expensive to
# keep testing primality on ones that have already been passed to
# this function. Since a prime number always remains prime, there
# is no need to recalculate the same input.

# For now, caching is commented out.


# @cache
def miller_rabin(n: int, k: int = 64) -> bool:
    """Checks if a number is a probable prime using Miller-Rabin primality testing.

    Examples:
    >>> miller_rabin(2)
    True
    >>> miller_rabin(35)
    False
    >>> miller_rabin(188)
    False
    >>> list(map(miller_rabin, [19, 2, 12, 13, 41, 43, 11, 7, 8]))
    [True, True, False, True, True, True, True, True, False]

    References:
        - https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
        - https://stackoverflow.com/a/29832947/12587354
    """
    # Find the integer pair (s, d) such that n = 2**s*d + 1
    # by factoring out powers of 2.
    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d >> 1
    # Repeat a witness loop for k random values in [2, n-2]
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x in {1, n - 1}:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


probable_prime = miller_rabin


@dataclass
class FiniteFieldElement:
    value: int
    mod: int

    def __post_init__(self) -> None:
        if self.mod <= 0:
            raise ValueError("Modulus must be positive.")
        if not probable_prime(self.mod):
            raise ValueError("Modulus must be a prime number.")
        self.value = self.value % self.mod

    def __str__(self) -> str:
        return str(self.value)

    def __int__(self) -> int:
        return self.value

    def inv(self) -> Self:
        """Returns the modular inverse of the field element."""
        return type(self)(modinv(self.value, self.mod), self.mod)

    def sqrt(self) -> Self | None:
        """Returns the modular square root of the field element (None if one doesn't exist)."""
        ret = tonelli(self.value, self.mod)
        return None if ret is None else type(self)(ret, self.mod)

    def __add__(self, other: Self | int) -> Self:
        if isinstance(other, type(self)):
            if other.mod != self.mod:
                raise ValueError("Elements are not a part of the same finite field.")
            return type(self)(self.value + other.value, self.mod)
        if isinstance(other, int):
            return type(self)(self.value + other, self.mod)
        raise TypeError(
            "Addition of {} is not allowed with {}".format(
                type(self).__name__, type(other).__name__
            )
        )

    __radd__ = __add__

    def __sub__(self, other: Self | int) -> Self:
        if isinstance(other, type(self)):
            if other.mod != self.mod:
                raise ValueError("Elements are not a part of the same finite field.")
            return type(self)(self.value - other.value, self.mod)
        if isinstance(other, int):
            return type(self)((self.value - other) % self.mod, self.mod)
        raise TypeError(
            "Subtraction of {} is not allowed with {}".format(
                type(self).__name__, type(other).__name__
            )
        )

    def __mul__(self, other: Self | int) -> Self:
        if isinstance(other, type(self)):
            if other.mod != self.mod:
                raise ValueError("Elements are not a part of the same finite field.")
            value = (self.value + other.value) % self.mod
            return type(self)(value, self.mod)
        if isinstance(other, int):
            value = (self.value * other) % self.mod
            return type(self)(value, self.mod)
        raise TypeError(
            "Multiplication of {} is not allowed with {}".format(
                type(self).__name__, type(other).__name__
            )
        )

    __rmul__ = __mul__

    def __pow__(self, exp: int) -> Self:
        # Since the modulus of the field element is prime,
        # the exponent can be reduced modulo (self.mod - 1)
        exp %= self.mod - 1
        return type(self)(
            pow(self.value, exp, self.mod),
            self.mod,
        )

    def __eq__(self, other: object) -> bool:
        # This is an equality check. Not congruence.
        if not isinstance(other, (type(self), int)):
            raise TypeError("Invalid type comparison.")
        if isinstance(other, type(self)):
            return self.value == other.value
        return self.value == other

    def __hash__(self) -> int:
        return hash(int(self))
