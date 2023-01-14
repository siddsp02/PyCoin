from src.secp256k1 import G, AffinePoint, Point, jacobi, tonelli


def test_point_from_int() -> None:
    p = AffinePoint.from_int(G)
    assert p == (
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )


def test_point_add() -> None:
    p = Point(
        0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
        0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
        0x1,
    )
    p2 = p + p
    p3 = p2 + p
    p5 = p2 + p3
    p10 = p5 + p5
    p23 = p10 + p10 + p3
    p33 = p23 + p10
    p56 = p23 + p33
    p89 = p56 + p33
    p122 = p89 + p33
    points = [p, p2, p3, p5, p10, p23, p33, p56, p89, p122]


def test_point_mul() -> None:
    p = Point.from_int(G)
    assert (p * 2).affine() == (
        0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
        0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
    )


def test_affine_point_add() -> None:
    p = AffinePoint.from_int(G)
    assert p + p == (
        0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
        0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
    )


def test_affine_point_neg() -> None:
    p = AffinePoint.from_int(G)
    x, y = p
    assert -p == (x, -y)


def test_affine_point_mul() -> None:
    p = AffinePoint.from_int(G)
    assert p * 2 == (
        0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
        0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
    )


def test_jacobi() -> None:
    vectors = [
        ((1, 1), 1),
        ((5, 3), -1),
        ((5, 11), 1),
        ((7, 3), 1),
        ((21, 13), -1),
    ]
    for (n, k), res in vectors:
        assert jacobi(n, k) == res


def test_tonelli() -> None:
    vectors = [
        ((44402, 100049), 30468),
        ((10, 13), 7),
        ((56, 101), 37),
        ((1030, 10009), 1632),
    ]
    for (n, p), res in vectors:
        assert tonelli(n, p) == res
