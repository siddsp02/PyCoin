import pytest
from src.crypto.field import FiniteFieldElement, miller_rabin


def test_miller_rabin() -> None:
    LARGE_PRIMES = [
        648391,
        718064159,
        7069067389,
        22742734291,
        36294260117,
        64988430769,
        136395369829,
        200147986693,
        243504973489,
        318083817907,
        435748987787,
    ]
    # All of these should return "True" since the sample of numbers is prime.
    assert all(map(miller_rabin, LARGE_PRIMES))
    LARGE_COMPOSITES = [
        130392,
        33333333333,
        999999999999,
        381933918195,
        3290932220,
    ]
    # All of these should return "False".
    assert not any(map(miller_rabin, LARGE_COMPOSITES))


def test_init() -> None:
    # Test initialization of values.
    with pytest.raises(ValueError):
        FiniteFieldElement(13, 0)
    with pytest.raises(ValueError):
        FiniteFieldElement(13, -5)
    x = FiniteFieldElement(239, 5)
    assert x.value == 4


def test_add() -> None:
    x = FiniteFieldElement(10, 11)
    y = FiniteFieldElement(13, 11)
    assert (x + y).value == 1
    x = FiniteFieldElement(29, 13)
    y = FiniteFieldElement(71, 13)
    assert (x + y).value == 9


def test_sub() -> None:
    x = FiniteFieldElement(412, 19)
    y = FiniteFieldElement(132, 19)
    assert (x - y).value == 14
