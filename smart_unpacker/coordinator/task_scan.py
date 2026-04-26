from typing import Any

from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.coordinator.context import RunContext
from smart_unpacker.detection import ArchiveTaskProvider


class ArchiveTaskScanner:
    def __init__(self, config: dict[str, Any], context: RunContext):
        self.context = context
        self.provider = ArchiveTaskProvider(config)
        self.detector = self.provider.detector

    def scan_root(self, scan_root: str) -> list[ArchiveTask]:
        return self.scan_targets([scan_root])

    def scan_targets(self, scan_roots: list[str]) -> list[ArchiveTask]:
        return self.provider.scan_targets(scan_roots, processed_keys=self.context.processed_keys)
