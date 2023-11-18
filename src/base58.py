from operator import not_

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode(s: bytes) -> str:
    """Encodes a bytes object to base58 format.

    References:
        - https://www.oreilly.com/library/view/programming-bitcoin/9781492031482/ch04.html
    """
    zeros = s.rindex(0) + 1
    assert all(map(not_, s[:zeros]))
    res = ""
    num = int.from_bytes(s, byteorder="big")
    while num > 0:
        num, mod = divmod(num, 58)
        res = ALPHABET[mod] + res
    return "1" * zeros + res
