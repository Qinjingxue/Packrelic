from pathlib import Path
from types import SimpleNamespace

from smart_unpacker.extraction.internal.split_stager import SplitVolumeStager
from smart_unpacker.relations.internal.group_builder import RelationsGroupBuilder


class FakeNativeTester:
    def __init__(self, ok: bool):
        self.ok = ok

    def test_archive(self, archive: str):
        return SimpleNamespace(ok=self.ok)


def _stager_with_candidates(candidates: list[str], *, test_ok: bool) -> SplitVolumeStager:
    stager = SplitVolumeStager.__new__(SplitVolumeStager)
    stager.seven_z_path = "7z.exe"
    stager._relations = RelationsGroupBuilder()
    stager._native_tester = FakeNativeTester(test_ok)
    stager._collect_misnamed_volume_candidates = lambda archive, all_parts, archive_prefix, style: list(candidates)
    return stager


def test_unverified_misnamed_candidates_are_not_cleanup_parts(tmp_path):
    first = tmp_path / "bundle.7z.001"
    candidate = tmp_path / "bundle"
    first.write_bytes(b"first")
    candidate.write_bytes(b"candidate")

    staged = _stager_with_candidates([str(candidate)], test_ok=False).stage(str(first), [str(first)])

    assert staged.archive == str(first)
    assert staged.run_parts == [str(first)]
    assert staged.cleanup_parts == [str(first)]
    assert staged.candidate_parts == [str(candidate)]
    assert staged.verified_candidates is False


def test_verified_misnamed_candidates_become_cleanup_parts(tmp_path):
    first = tmp_path / "bundle.7z.001"
    candidate = tmp_path / "bundle"
    first.write_bytes(b"first")
    candidate.write_bytes(b"candidate")

    stager = _stager_with_candidates([str(candidate)], test_ok=True)
    staged = stager.stage(str(first), [str(first)])

    assert Path(staged.archive).name == "bundle.7z.001"
    assert staged.archive != str(first)
    assert staged.run_parts == [str(first), str(candidate)]
    assert staged.cleanup_parts == [str(first), str(candidate)]
    assert staged.candidate_parts == [str(candidate)]
    assert staged.verified_candidates is True

    temp_dir = staged.temp_dir
    assert temp_dir
    stager.cleanup(staged)
    assert not Path(temp_dir).exists()
