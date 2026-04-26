from typing import Any

from smart_unpacker.detection import NestedOutputScanPolicy


class OutputScanPolicy(NestedOutputScanPolicy):
    """Coordinator compatibility facade for recursive output scan decisions."""

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
