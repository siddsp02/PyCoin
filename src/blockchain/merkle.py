"""The merkle tree for Bitcoin."""

import base64
from dataclasses import dataclass
from functools import reduce
from itertools import starmap, zip_longest
from typing import Iterable, Iterator, Literal, Sequence

from ..utils import sha256d

LEFT, RIGHT = 0, 1

Direction = Literal[0] | Literal[1]
ProofElement = tuple[Direction, bytes]
MerkleProof = list[ProofElement]


@dataclass
class MerkleTree:
    txs: list[bytes]

    def __str__(self) -> str:
        # Base 64 is used to make string representation shorter.
        # This might be changed to used hexadecimal in the future.

        def b64(s):
            """Internal base64 conversion utility."""
            return base64.b64encode(s).decode()

        # For a better informal string representation, the string length
        # of the first level in the merkle tree is taken, and then the
        # levels that come after are formatted to be a centered string
        # of the same size. The code here is a little bit hard to read,
        # but will be refactored in the future.

        levels = self.levels
        size = len(" ".join(map(b64, levels[0])))
        # Each level is on its own line when converted to a string.
        ret = "\n".join(
            f"{' '.join(map(b64, level)):^{size}}" for level in reversed(levels)
        )
        return ret

    @property
    def root(self) -> bytes:
        """Returns the root hash of the merkle tree."""
        return hash_tree(self.txs)

    @property
    def levels(self) -> list[list[bytes]]:
        """Returns a list of the levels of the merkle tree."""
        return list(self.iter_levels())

    def iter_levels(self) -> Iterator[list[bytes]]:
        return iter_levels(self.txs)

    def get_proof(self, tx: bytes) -> MerkleProof:
        """Returns a proof of inclusion for a transaction hash."""
        return create_proof(self.txs, tx)

    def verify(self, tx: bytes, proof: MerkleProof) -> bool:
        """Verifies that a transaction is in the merkle tree when given
        its corresponding proof and transaction hash.
        """
        return verify_proof(tx, proof, self.root)


def iter_levels(merkle_tree: Iterable[bytes]) -> Iterator[list[bytes]]:
    """Iterates over the levels of a merkle tree, each new level being
    the result of the hashed pairs of items from the previous level.
    """
    level = list(merkle_tree)
    while len(level) > 1:
        yield level
        level = list(starmap(hash_pair, pairs(level)))
    yield level


def pairs(values: Sequence[bytes]) -> Iterator[tuple[bytes, bytes]]:
    """Groups a sequence of bytes into pairs. If the length of
    the sequence is odd, the last item is paired with itself.
    """
    args, last = [iter(values)] * 2, values[-1]
    return zip_longest(*args, fillvalue=last)  # type: ignore


def hash_pair(v1: bytes, v2: bytes) -> bytes:
    """Double hashes a pair of bytes using SHA-256."""
    ret = (v2 + v1)[::-1]
    ret = sha256d(ret)[::-1]
    return ret


def hash_tree(merkle_tree: Iterable[bytes]) -> bytes:
    """Hashes all the transactions in a merkle tree, and returns the root hash.

    Transactions are stored as a sequence of bytes/char arrays, where each pair
    is concatenated and hashed recursively until there is only a single array
    or sequence of bytes remaining.

    Examples:
    >>> # Block 125552 on Bitcoin:
    >>> txs = map(bytes.fromhex,                                                  \
              ["51d37bdd871c9e1f4d5541be67a6ab625e32028744d7d4609d0c37747b40cd2d",\
               "60c25dda8d41f8d3d7d5c6249e2ea1b05a25bf7ae2ad6d904b512b31f997e1a1",\
               "01f314cdd8566d3e5dbdd97de2d9fbfbfd6873e916a00d48758282cbb81a45b9",\
               "b519286a1040da6ad83c783eb2872659eaf57b1bec088e614776ffe7dc8f6d01"]\
        )
    >>> result = hash_tree(txs)
    >>> result.hex()  # Convert results.
    '2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3'

    References:
        - https://gutier.io/post/programming-tutorial-blockchain-haskell-merkle-tree/
        - https://en.bitcoin.it/wiki/Protocol_documentation#Merkle%5FTrees
    """
    *_, result = iter_levels(merkle_tree)
    return result.pop()


def create_proof(merkle_tree: Iterable[bytes], tx: bytes) -> MerkleProof:
    """Creates the sequence of proofs necessary to be able to reproduce
    the root-hash of the merkle tree so an SPV wallet can quickly and
    compactly verify that their transaction was included in a block.

    Examples:
    >>> # Example from references (block 234132).
    >>> txs = map(bytes.fromhex,                                                \
            ["1877fc02dfb78b83b913c0eef8fa5990a55dd4a56449faf97a0dcb6f04cff32b",\
             "94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05",\
             "80a2726fbbe93a8a74bc5a357274510e6a00dfd50489a13c396d2c288e106ec2",\
             "5a3e9111cc3a69cc26d290578d46fb40ba1d4abcf706487a1b6d03730d3bdf02"]\
        )
    >>> create_proof(txs, bytes.fromhex("94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05"))
    [(0, b'\\x18w\\xfc\\x02\\xdf\\xb7\\x8b\\x83\\xb9\\x13\\xc0\\xee\\xf8\\xfaY\\x90\\xa5]\\xd4\\xa5dI\\xfa\\xf9z\\r\\xcbo\\x04\\xcf\\xf3+'), \
(1, b'\\x914\\x89\\xacl\\x00\\x15t\\xf5!\\x8aM-\\r\\xe1\\xd5\\x92X\\xe6c\\xd2\\xdf\\xc0\\xf0\\x91\\xb6\\xb3\\x02\\xae,\\xb45')]


    References:
        - https://gutier.io/post/programming-tutorial-blockchain-haskell-merkle-tree/
    """
    tree = list(merkle_tree)
    item = tx
    proof = []
    while len(tree) > 1:
        # Find the next pair which includes our search element,
        # and append the sibling node to the proof list.
        left, right = next(pair for pair in pairs(tree) if item in pair)
        # Direction is also added to the proof list, so the order
        # of concatenation is known to anyone trying to verify the
        # proof itself.
        pair = (RIGHT, right) if item == left else (LEFT, left)
        item = hash_pair(left, right)
        proof.append(pair)
        tree[:] = starmap(hash_pair, pairs(tree))
    return proof


def hash_element(x: bytes, elem: ProofElement) -> bytes:
    direction, value = elem
    return hash_pair(value, x) if direction == LEFT else hash_pair(x, value)


def verify_proof(tx: bytes, proof: MerkleProof, root: bytes) -> bool:
    """Verifies a merkle proof by consuming and updating the sha256
    hashes of transaction hash pairs.
    """
    return reduce(hash_element, proof, tx) == root
