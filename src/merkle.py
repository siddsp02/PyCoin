"""The merkle tree for Bitcoin. Later on, regular hashing may be
swapped for update functions to speed up hashing and concatenation.
"""

import doctest
from functools import lru_cache
from itertools import starmap, zip_longest
from typing import Iterable, Iterator, Literal, Sequence, TypeVar

try:
    from .utils import sha256d
except ImportError:
    from utils import sha256d

Direction = Literal["left", "right"]
ProofElement = tuple[Direction, bytes]
MerkleProof = list[ProofElement]

T = TypeVar("T", bound=bytes)


def pairs(values: Sequence[bytes]) -> Iterator[tuple[bytes, bytes]]:
    """Groups a sequence of bytes into pairs. If the length of
    the sequence is odd, the last item is paired with itself.
    """
    args, last = [iter(values)] * 2, values[-1]
    return zip_longest(*args, fillvalue=last)  # type: ignore


# Hashing multiple pairs maybe computationally expensive,
# especially since multiple proofs involving the same pairs
# may be used. This might especially be useful when the
# function for constructing proofs is changed later on to
# be defined recursively.
@lru_cache(maxsize=1000)
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
    tree = list(merkle_tree)
    while len(tree) > 1:
        tree[:] = starmap(hash_pair, pairs(tree))
    return tree.pop()


def create_proof(merkle_tree: Sequence[bytes], tx: bytes) -> MerkleProof:
    """Creates the sequence of proofs necessary to be able to reproduce
    the root-hash of the merkle tree so an SPV wallet can quickly and
    compactly verify that their transaction was included in a block.

    Proofs are created under the assumption that "Alice" can compute pair
    hashes from only the missing elements.

    Note: While the following code was translated from Haskell to Python,
    the following translation is my own. The Haskell version was quite
    difficult to understand, since steps did not translate in a way that
    was simple to implement.

    To add, the following code is not complete. There are still issues
    with trying to create merkle proofs properly.
    
    Examples:
    >>> txs = map(bytes.fromhex,                                                \
            ["1877fc02dfb78b83b913c0eef8fa5990a55dd4a56449faf97a0dcb6f04cff32b",\
             "94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05",\
             "80a2726fbbe93a8a74bc5a357274510e6a00dfd50489a13c396d2c288e106ec2",\
             "5a3e9111cc3a69cc26d290578d46fb40ba1d4abcf706487a1b6d03730d3bdf02"]\
        )
    >>> tx = bytes.fromhex("94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05")
    >>> create_proof(txs, tx)
    None

    References:
        - https://gutier.io/post/programming-tutorial-blockchain-haskell-merkle-tree/
    """
    tree = list(merkle_tree)
    item = tx
    combined_pairs = []
    proof_sequence = []
    while len(tree) > 1:
        # Find the next pair which includes our search element,
        # and append the sibling node to the proof list.
        pair = next(pair for pair in pairs(tree) if item in pair)
        (left, right) = pair
        # Direction is also added to the proof list, so the order
        # of concatenation is known to anyone trying to verify the
        # proof itself.
        proof_element = ("right", right) if item == left else ("left", left)
        item = hash_pair(left, right)
        proof_sequence.append(proof_element)
        combined_pairs.append(item)
        tree[:] = starmap(hash_pair, pairs(tree))
    return proof_sequence


def verify_proof(merkle_tree: Iterable[bytes], tx: bytes) -> bool:
    """Verifies a merkle proof by consuming and updating the sha256
    hashes of transaction hash pairs."""
    ...


def verify_root(merkle_tree: Iterable[bytes], root_hash: bytes) -> bool:
    return hash_tree(merkle_tree) == root_hash


if __name__ == "__main__":
    # doctest.testmod()
    tree = list(
        map(
            bytes.fromhex,
            [
                "1877fc02dfb78b83b913c0eef8fa5990a55dd4a56449faf97a0dcb6f04cff32b",
                "94d67aa1720ef6b58d130e39f3b7b4e5e7dab07698ab6baf1465e7e639115e05",
                "80a2726fbbe93a8a74bc5a357274510e6a00dfd50489a13c396d2c288e106ec2",
                "5a3e9111cc3a69cc26d290578d46fb40ba1d4abcf706487a1b6d03730d3bdf02",
            ],
        )
    )
