from typing import Any

from sunpack.filesystem.filters.base import ScanCandidate, ScanDecision, keep, reject


class NumericRange:
    def __init__(
        self,
        *,
        gt: int | None = None,
        gte: int | None = None,
        lt: int | None = None,
        lte: int | None = None,
        eq: int | None = None,
    ):
        self.gt = gt
        self.gte = gte
        self.lt = lt
        self.lte = lte
        self.eq = eq

    @property
    def configured(self) -> bool:
        return any(value is not None for value in (self.gt, self.gte, self.lt, self.lte, self.eq))

    @property
    def native_minimum(self) -> int | None:
        if self.eq is not None:
            return self.eq
        minimums = []
        if self.gte is not None:
            minimums.append(self.gte)
        if self.gt is not None:
            minimums.append(self.gt + 1)
        return max(minimums) if minimums else None

    @classmethod
    def from_config(cls, config: dict[str, Any], *, legacy_min_key: str | None = None):
        return cls(
            gt=_int_or_none(_first(config, "gt", "greater_than")),
            gte=_int_or_none(_first(config, "gte", "greater_than_or_equal", "min", "minimum", legacy_min_key)),
            lt=_int_or_none(_first(config, "lt", "less_than")),
            lte=_int_or_none(_first(config, "lte", "less_than_or_equal", "max", "maximum")),
            eq=_int_or_none(_first(config, "eq", "equal", "equals")),
        )

    def allows(self, value: int | None) -> bool:
        if not self.configured:
            return True
        if value is None or value < 0:
            return False
        if self.eq is not None and value != self.eq:
            return False
        if self.gt is not None and value <= self.gt:
            return False
        if self.gte is not None and value < self.gte:
            return False
        if self.lt is not None and value >= self.lt:
            return False
        if self.lte is not None and value > self.lte:
            return False
        return True


class SizeRangeScanFilter:
    name = "size_range"
    stage = "size"

    def __init__(self, value_range: NumericRange | None = None):
        self.value_range = value_range or NumericRange()
        self.min_inspection_size_bytes = self.value_range.native_minimum

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(NumericRange.from_config(config, legacy_min_key="min_inspection_size_bytes"))

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        if candidate.kind != "file":
            return keep()
        if not self.value_range.configured:
            return keep()
        if not self.value_range.allows(candidate.size):
            return reject(f"File size outside configured range: {candidate.size}")
        return keep()


class SizeMinimumScanFilter(SizeRangeScanFilter):
    name = "size_minimum"


def _first(config: dict[str, Any], *keys: str | None):
    for key in keys:
        if key and key in config:
            return config.get(key)
    return None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
