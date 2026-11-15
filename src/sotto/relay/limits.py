"""The token buckets of docs/protocol.md, section 12.2, kept in the memory of the process."""

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(slots=True)
class Bucket:
    tokens: float
    updated_at: float


class TokenBuckets:
    """One bucket per key: full when it is made, one token back per `refill_seconds`.

    `clock` is monotonic; a bucket that is full again is forgotten by `forget_full`.
    """

    def __init__(self, size: int, refill_seconds: float, clock: Callable[[], float]) -> None:
        self.size = size
        self.refill_seconds = refill_seconds
        self.clock = clock
        self.buckets: dict[bytes, Bucket] = {}

    def has_token(self, key: bytes) -> bool:
        return self._refilled(key).tokens >= 1

    def take(self, key: bytes) -> bool:
        """Takes one token of the bucket of `key`; False when the bucket has none."""
        bucket = self._refilled(key)
        if bucket.tokens < 1:
            return False
        bucket.tokens -= 1
        self.buckets[key] = bucket
        return True

    def forget_full(self) -> None:
        full = [key for key in self.buckets if self._refilled(key).tokens >= self.size]
        for key in full:
            del self.buckets[key]

    def _refilled(self, key: bytes) -> Bucket:
        now = self.clock()
        bucket = self.buckets.get(key)
        if bucket is None:
            return Bucket(tokens=self.size, updated_at=now)

        returned = (now - bucket.updated_at) / self.refill_seconds
        bucket.tokens = min(self.size, bucket.tokens + returned)
        bucket.updated_at = now
        return bucket
