import time
import zipfile
from binascii import crc32

import smart_unpacker_native

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


def _rar4_block(header_type: int, flags: int = 0, payload: bytes = b"") -> bytes:
    add_size = len(payload).to_bytes(4, "little") if payload else b""
    header_size = 7 + len(add_size)
    body = bytes([header_type]) + flags.to_bytes(2, "little") + header_size.to_bytes(2, "little") + add_size
    header_crc = (crc32(body) & 0xFFFF).to_bytes(2, "little")
    return header_crc + body + payload


def _rar4_bytes() -> bytes:
    return b"Rar!\x1a\x07\x00" + _rar4_block(0x73) + _rar4_block(0x7B)


def _seven_zip_bytes() -> bytes:
    gap = b"abcde"
    next_header = b"\x01"
    start_header = len(gap).to_bytes(8, "little") + len(next_header).to_bytes(8, "little") + crc32(next_header).to_bytes(4, "little")
    return b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + crc32(start_header).to_bytes(4, "little") + start_header + gap + next_header


def test_analysis_scheduler_finds_embedded_archive_segments(tmp_path):
    zip_start = len(b"shell-a")
    zip_data = _zip_bytes(tmp_path)
    rar_data = _rar4_bytes()
    payload = (
        b"shell-a"
        + zip_data
        + b"shell-b"
        + rar_data
        + b"shell-c"
    )
    path = tmp_path / "mixed.bin"
    path.write_bytes(payload)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    by_format = {item.format: item for item in report.evidences}

    assert by_format["zip"].status == "extractable"
    assert by_format["zip"].confidence == 0.99
    assert by_format["zip"].segments[0].start_offset == zip_start
    assert by_format["zip"].segments[0].end_offset == zip_start + len(zip_data)
    assert by_format["rar"].status == "extractable"
    assert by_format["rar"].confidence == 0.97
    assert by_format["rar"].segments[0].start_offset == payload.index(b"Rar!")
    assert by_format["rar"].segments[0].end_offset == payload.index(b"Rar!") + len(rar_data)
    assert by_format["7z"].status == "not_found"
    assert by_format["7z"].confidence == 0.0
    assert {item.format for item in report.selected} == {"zip", "rar"}


def test_analysis_scheduler_prefers_structural_boundary_over_next_signature(tmp_path):
    rar_data = _rar4_bytes()
    seven_data = _seven_zip_bytes()
    payload = b"shell" + rar_data + b"noise" + seven_data
    path = tmp_path / "mixed.bin"
    path.write_bytes(payload)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    by_format = {item.format: item for item in report.evidences}

    assert by_format["rar"].segments[0].end_offset == len(b"shell") + len(rar_data)
    assert by_format["7z"].segments[0].start_offset == payload.index(b"7z\xbc\xaf\x27\x1c")
    assert by_format["7z"].confidence == 0.97


def test_analysis_scheduler_walks_rar4_blocks_to_endarc(tmp_path):
    rar_data = _rar4_bytes()
    payload = b"shell" + rar_data + b"tail-shell"
    path = tmp_path / "rar4.bin"
    path.write_bytes(payload)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    rar = {item.format: item for item in report.evidences}["rar"]

    assert rar.status == "extractable"
    assert rar.confidence == 0.97
    assert rar.segments[0].start_offset == len(b"shell")
    assert rar.segments[0].end_offset == len(b"shell") + len(rar_data)
    assert not rar.warnings
    assert rar.details["end_block_found"] is True


def test_analysis_scheduler_uses_7z_start_header_for_segment_end(tmp_path):
    seven_data = _seven_zip_bytes()
    payload = b"shell" + seven_data + b"tail-shell"
    path = tmp_path / "seven.bin"
    path.write_bytes(payload)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    seven = {item.format: item for item in report.evidences}["7z"]

    assert seven.status == "extractable"
    assert seven.confidence == 0.97
    assert seven.segments[0].start_offset == len(b"shell")
    assert seven.segments[0].end_offset == len(b"shell") + len(seven_data)
    assert not seven.warnings
    assert seven.details["next_header_crc_ok"] is True


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

    if hasattr(smart_unpacker_native, "AnalysisBinaryView"):
        assert view._native is not None
    assert view.read_at(0, 3) == b"abc"
    assert view.read_at(0, 3) == b"abc"

    stats = view.stats()
    assert stats.read_bytes == 3
    assert stats.cache_hits == 1


def test_shared_binary_view_enforces_read_budget(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abcdef")
    view = SharedBinaryView(str(path), cache_bytes=0, max_read_bytes=2)

    try:
        view.read_at(0, 3)
    except RuntimeError as exc:
        assert "read budget" in str(exc)
    else:
        raise AssertionError("read budget should be enforced")


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
