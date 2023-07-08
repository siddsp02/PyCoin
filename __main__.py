import multiprocessing as mp
import time

from src.blockchain.miner import BlockHeader
from src.constants import UINT32_MAX, WORKERS


def main() -> None:
    # This is just an example of mining the genesis block.
    # Mining works, but it is slow since looping in Python
    # is expensive.
    block = BlockHeader.from_json("example_blocks/genesis.json")
    start = 2_080_000_000
    t1 = time.perf_counter()
    with mp.Pool(processes=WORKERS) as pool:
        results = pool.imap(
            block._check_nonce, range(start, UINT32_MAX), chunksize=20_000
        )
        nonce = next(i for i, val in enumerate(results, start) if val)
    t2 = time.perf_counter()
    if nonce is None:
        print("Nonce not found.")
    else:
        print(f"Block mined with {nonce=}")
    print(f"Time taken = {t2-t1:.8f} seconds")
    if nonce is not None:
        print(f"Hashrate: {(nonce-start)//(t2-t1)} H/s")


if __name__ == "__main__":
    main()
