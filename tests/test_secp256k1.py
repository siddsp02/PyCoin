from itertools import starmap
from operator import eq
import pytest

from src.secp256k1 import G, Point, jacobi, tonelli


def test_point_add() -> None:
    p = G
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
    res = [
        (
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        ),
        (
            0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
            0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
        ),
        (
            0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
            0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672,
        ),
        (
            0x2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4,
            0xD8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6,
        ),
        (
            0xA0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7,
            0x893ABA425419BC27A3B6C7E693A24C696F794C2ED877A1593CBEE53B037368D7,
        ),
        (
            0x2FA2104D6B38D11B0230010559879124E42AB8DFEFF5FF29DC9CDADD4ECACC3F,
            0x2DE1068295DD865B64569335BD5DD80181D70ECFC882648423BA76B532B7D67,
        ),
        (
            0x1697FFA6FD9DE627C077E3D2FE541084CE13300B0BEC1146F95AE57F0D0BD6A5,
            0xB9C398F186806F5D27561506E4557433A2CF15009E498AE7ADEE9D63D01B2396,
        ),
        (
            0xBCE74DE6D5F98DC027740C2BBFF05B6AAFE5FD8D103F827E48894A2BD3460117,
            0x5BEA1FA17A41B115525A3E7DBF0D8D5A4F7CE5C6FC73A6F4F216512417C9F6B4,
        ),
        (
            0xD3CC30AD6B483E4BC79CE2C9DD8BC54993E947EB8DF787B442943D3F7B527EAF,
            0x8B378A22D827278D89C5E9BE8F9508AE3C2AD46290358630AFB34DB04EEDE0A4,
        ),
        (
            0x139AE46A1133F1F9D23F25EFBA0F6DD87BF7DDAF568A5FB9E0A3BFDA73176237,
            0x995E555C8AABD263FD238833A12188B8A5FFBEB480BA0E3E6EC481A8991472,
        ),
    ]
    assert all(map(lambda x, y: x.affine() == y, points, res))


def test_point_mul() -> None:
    assert (G * 2).affine() == (
        0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
        0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
    )


@pytest.mark.parametrize(
    "args, res", [((1, 1), 1), ((5, 3), -1), ((5, 11), 1), ((7, 3), 1), ((21, 13), -1)]
)
def test_jacobi(args: tuple[int, int], res: int) -> None:
    assert jacobi(*args) == res


@pytest.mark.parametrize(
    "args, res",
    [((44402, 100049), 30468), ((10, 13), 7), ((56, 101), 37), ((1030, 10009), 1632)],
)
def test_tonelli(args: tuple[int, int], res: int) -> None:
    assert tonelli(*args) == res
