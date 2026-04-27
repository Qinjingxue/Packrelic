import time
import zipfile

from smart_unpacker.analysis.pipeline.module import AnalysisModuleSpec
from smart_unpacker.analysis.pipeline.registry import get_analysis_module_registry
from smart_unpacker.analysis.result import ArchiveFormatEvidence
from smart_unpacker.analysis.scheduler import ArchiveAnalysisScheduler
from smart_unpacker.analysis.view import SharedBinaryView


def _zip_bytes(tmp_path):
    archive = tmp_path / "inner.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("marker.txt", "hello")
    return archive.read_bytes()


def test_analysis_scheduler_finds_embedded_archive_segments(tmp_path):
    payload = (
        b"shell-a"
        + _zip_bytes(tmp_path)
        + b"shell-b"
        + b"Rar!\x1a\x07\x01\x00rar-payload"
        + b"shell-c"
        + b"7z\xbc\xaf\x27\x1cseven"
    )
    path = tmp_path / "mixed.bin"
    path.write_bytes(payload)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    by_format = {item.format: item for item in report.evidences}

    assert by_format["zip"].status == "extractable"
    assert by_format["zip"].confidence >= 0.85
    assert by_format["zip"].segments[0].start_offset == len(b"shell-a")
    assert by_format["rar"].segments[0].start_offset == payload.index(b"Rar!")
    assert by_format["7z"].segments[0].start_offset == payload.index(b"7z\xbc\xaf\x27\x1c")
    assert {item.format for item in report.selected} == {"zip", "rar", "7z"}


def test_analysis_module_config_can_disable_formats(tmp_path):
    path = tmp_path / "payload.bin"
    path.write_bytes(_zip_bytes(tmp_path) + b"Rar!\x1a\x07\x00")

    report = ArchiveAnalysisScheduler({
        "analysis": {
            "modules": [
                {"name": "zip", "enabled": True},
                {"name": "rar", "enabled": False},
                {"name": "seven_zip", "enabled": False},
            ],
        },
    }).analyze_path(str(path))

    assert [item.format for item in report.evidences] == ["zip"]


def test_shared_binary_view_reuses_cached_reads(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abcdef")
    view = SharedBinaryView(str(path), cache_bytes=1024)

    assert view.read_at(0, 3) == b"abc"
    assert view.read_at(0, 3) == b"abc"

    stats = view.stats()
    assert stats.read_bytes == 3
    assert stats.cache_hits == 1


class _SlowModule:
    def __init__(self, name: str):
        self.spec = AnalysisModuleSpec(name=name, formats=(name,), signatures=(name.encode("ascii"),))

    def analyze(self, view, prepass, config):
        time.sleep(0.15)
        return ArchiveFormatEvidence(format=self.spec.name, confidence=0.0, status="not_found")


def test_analysis_scheduler_runs_modules_in_parallel(tmp_path):
    registry = get_analysis_module_registry()
    first = _SlowModule("slow_a")
    second = _SlowModule("slow_b")
    registry.register(first)
    registry.register(second)
    path = tmp_path / "slow.bin"
    path.write_bytes(b"slow_a slow_b")

    start = time.perf_counter()
    ArchiveAnalysisScheduler({
        "analysis": {
            "parallel": True,
            "max_workers": 2,
            "modules": [
                {"name": "slow_a", "enabled": True},
                {"name": "slow_b", "enabled": True},
            ],
        },
    }).analyze_path(str(path))
    elapsed = time.perf_counter() - start

    assert elapsed < 0.28
