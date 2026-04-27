import os
import threading
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True)
class ReadStats:
    read_bytes: int
    cache_hits: int


class SharedBinaryView:
    """Thread-safe random-access binary view with a small shared LRU cache."""

    def __init__(
        self,
        path: str,
        *,
        cache_bytes: int = 64 * 1024 * 1024,
        max_read_bytes: int | None = None,
        max_concurrent_reads: int = 1,
    ):
        self.path = path
        self.size = os.path.getsize(path)
        self.cache_bytes = max(0, int(cache_bytes or 0))
        self.max_read_bytes = max_read_bytes if max_read_bytes is None else max(0, int(max_read_bytes))
        self._read_semaphore = threading.Semaphore(max(1, int(max_concurrent_reads or 1)))
        self._cache: OrderedDict[tuple[int, int], bytes] = OrderedDict()
        self._cache_size = 0
        self._lock = threading.Lock()
        self._read_bytes = 0
        self._cache_hits = 0

    def read_at(self, offset: int, size: int) -> bytes:
        offset = max(0, int(offset))
        size = max(0, int(size))
        if offset >= self.size or size <= 0:
            return b""
        size = min(size, self.size - offset)
        key = (offset, size)
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache_hits += 1
                self._cache.move_to_end(key)
                return cached
            self._reserve_read_budget(size)

        with self._read_semaphore:
            with open(self.path, "rb") as handle:
                handle.seek(offset)
                data = handle.read(size)

        with self._lock:
            self._read_bytes += len(data)
            self._store_cache_entry(key, data)
        return data

    def read_tail(self, size: int) -> bytes:
        size = min(max(0, int(size)), self.size)
        return self.read_at(max(0, self.size - size), size)

    def stats(self) -> ReadStats:
        with self._lock:
            return ReadStats(read_bytes=self._read_bytes, cache_hits=self._cache_hits)

    def _reserve_read_budget(self, size: int) -> None:
        if self.max_read_bytes is None:
            return
        if self._read_bytes + size > self.max_read_bytes:
            raise RuntimeError("archive analysis read budget exceeded")

    def _store_cache_entry(self, key: tuple[int, int], data: bytes) -> None:
        if self.cache_bytes <= 0 or len(data) > self.cache_bytes:
            return
        self._cache[key] = data
        self._cache.move_to_end(key)
        self._cache_size += len(data)
        while self._cache_size > self.cache_bytes and self._cache:
            _, old = self._cache.popitem(last=False)
            self._cache_size -= len(old)
