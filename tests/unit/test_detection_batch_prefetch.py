from pathlib import Path

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection.internal.scan_session import DetectionScanSession
from smart_unpacker.detection.pipeline.facts.batch_provider import BatchFactProvider
from smart_unpacker.detection.pipeline.facts.registry import discover_collectors
from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.identity import file_identity_for_context
from smart_unpacker.support.path_keys import path_key


def test_batch_file_head_prefetch_sets_size_mtime_and_magic(tmp_path):
    discover_collectors()
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK\x03\x04payload")
    bag = FactBag()
    bag.set("file.path", str(archive))
    session = DetectionScanSession(config={})

    BatchFactProvider(scan_session=session).prefill_facts(
        [bag],
        {"file.size", "file.magic_bytes"},
    )

    assert bag.get("file.size") == archive.stat().st_size
    assert isinstance(bag.get("file.mtime_ns"), int)
    assert bag.get("file.magic_bytes") == b"PK\x03\x04payload"[:16]


def test_scene_marker_batch_uses_unfiltered_snapshot_for_small_runtime_files(tmp_path):
    discover_collectors()
    root = tmp_path / "game"
    marker = root / "www" / "js" / "rpg_core.js"
    archive = root / "www" / "data" / "asset.zip"
    marker.parent.mkdir(parents=True)
    archive.parent.mkdir(parents=True)
    marker.write_text("// tiny marker", encoding="utf-8")
    archive.write_bytes(b"PK\x03\x04")
    bag = FactBag()
    bag.set("file.path", str(archive))
    session = DetectionScanSession(config={
        "filesystem": {
            "scan_filters": [
                {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 1024 * 1024},
            ],
        }
    })

    BatchFactProvider(scan_session=session).prefill_facts([bag], {"scene.directory_markers"})

    markers = {
        marker_name
        for item in bag.get("scene.directory_markers") or []
        for marker_name in item.get("markers", [])
    }
    assert "rpg_core" in markers


def test_processor_identity_uses_prefetched_file_facts(monkeypatch, tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"7z")
    bag = FactBag()
    bag.set("file.path", str(archive))
    bag.set("file.size", 2)
    bag.set("file.mtime_ns", 12345)
    context = FactProcessorContext(
        fact_bag=bag,
        output_fact="dummy",
        config={},
        fact_config={},
    )

    monkeypatch.setattr(
        "smart_unpacker.detection.pipeline.processors.identity.file_identity",
        lambda _path: (_raise("file_identity should not be called")),
    )

    assert file_identity_for_context(context, str(archive)) == (
        path_key(archive),
        2,
        12345,
    )


def _raise(message):
    raise AssertionError(message)
