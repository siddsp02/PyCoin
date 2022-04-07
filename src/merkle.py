"""The merkle tree for Bitcoin. Later on, regular hashing may be
swapped for update functions to speed up hashing and concatenation.
"""

import doctest
from functools import lru_cache
from itertools import starmap, zip_longest
from typing import Iterable, Iterator, Literal, Sequence, TypeVar

from utils import sha256d

Direction = Literal["left", "right"]
ProofElement = tuple[Direction, bytes]
ProofList = list[ProofElement]
PairList = list[bytes]
MerkleProof = tuple[ProofList, PairList]

T = TypeVar("T", bound=bytes)


def pairs(values: Sequence[bytes]) -> Iterator[bytes]:
    """Groups a sequence of bytes into pairs. If the length of
    the sequence is odd, the last item is paired with itself.
    """
    evens, odds = values[0::2], values[1::2]
    longest = max(evens, odds, key=len)
    last = longest[-1]
    return zip_longest(evens, odds, fillvalue=last)


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
    >>> txs = ["51d37bdd871c9e1f4d5541be67a6ab625e32028744d7d4609d0c37747b40cd2d",\
               "60c25dda8d41f8d3d7d5c6249e2ea1b05a25bf7ae2ad6d904b512b31f997e1a1",\
               "01f314cdd8566d3e5dbdd97de2d9fbfbfd6873e916a00d48758282cbb81a45b9",\
               "b519286a1040da6ad83c783eb2872659eaf57b1bec088e614776ffe7dc8f6d01"]
    >>> tx_bytes = map(bytes.fromhex, txs)
    >>> result = hash_tree(tx_bytes)
    >>> result.hex()  # Convert results.
    '2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3'

    References:
        - https://gutier.io/post/programming-tutorial-blockchain-haskell-merkle-tree/
        - https://en.bitcoin.it/wiki/Protocol_documentation#Merkle%5FTrees
    """
    tree = list(merkle_tree)
    while len(tree) > 1:
        tree[:] = pairs(tree)
        tree[:] = starmap(hash_pair, tree)
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

    References:
        - https://gutier.io/post/programming-tutorial-blockchain-haskell-merkle-tree/
    """
    tree = list(merkle_tree)
    item = tx
    combined_pairs = []
    proof_sequence = []
    while len(tree) > 1:
        tree[:] = pairs(tree)
        # Find the next pair which includes our search element,
        # and append the sibling node to the proof list.
        pair = next(pair for pair in tree if item in pair)
        (left, right) = pair
        # Direction is also added to the proof list, so the order
        # of concatenation is known to anyone trying to verify the
        # proof itself.
        proof_element = ("right", right) if item == left else ("left", left)
        item = hash_pair(*pair)
        proof_sequence.append(proof_element)
        combined_pairs.append(item)
        tree[:] = starmap(hash_pair, tree)
    return proof_sequence, combined_pairs


# fmt: on


def verify_proof(merkle_tree: Iterable[bytes], tx: bytes) -> bool:
    """Verifies a merkle proof by consuming and updating the sha256
    hashes of transaction hash pairs."""
    ...


def verify_root(merkle_tree: Iterable[bytes], root_hash: bytes) -> bool:
    return hash_tree(merkle_tree) == root_hash


if __name__ == "__main__":
    doctest.testmod()
