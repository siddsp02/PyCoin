"""Consensus rules and constants."""

# fmt: off

MAX_BLOCK_SIZE = 33_554_432             # Protocol limit before soft fork (32 MiB).
MAX_LEGACY_BLOCK_SIZE = 1_000_000       # Current Bitcoin Core blocksize limit.
EXCESSIVE_MAX_BLOCK_SIZE = 32_000_000   # Maximum limit (no recompilation needed).

MAX_TRANSACTION_SIZE = 100_000
