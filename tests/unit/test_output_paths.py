from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.internal.workflow.output_paths import default_output_dir_for_task


def _task(path, logical_name="archive"):
    return ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=logical_name,
    )


def test_default_output_dir_uses_archive_parent_without_output_config(tmp_path):
    archive = tmp_path / "input" / "payload.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"zip")

    out_dir = default_output_dir_for_task(_task(archive, "payload"))

    assert out_dir == str(tmp_path / "input" / "payload")


def test_output_root_preserves_relative_parent(tmp_path):
    input_root = tmp_path / "input"
    archive = input_root / "sub" / "payload.zip"
    output_root = tmp_path / "out"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"zip")

    out_dir = default_output_dir_for_task(
        _task(archive, "payload"),
        {"root": str(output_root), "common_root": str(input_root)},
    )

    assert out_dir == str(output_root / "sub" / "payload")


def test_output_root_uses_root_for_common_root_child(tmp_path):
    input_root = tmp_path / "input"
    archive = input_root / "payload.zip"
    output_root = tmp_path / "out"
    input_root.mkdir()
    archive.write_bytes(b"zip")

    out_dir = default_output_dir_for_task(
        _task(archive, "payload"),
        {"root": str(output_root), "common_root": str(input_root)},
    )

    assert out_dir == str(output_root / "payload")
