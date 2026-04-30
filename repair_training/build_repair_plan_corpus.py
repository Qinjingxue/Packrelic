from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from repair_training.training_corruption import build_corpus_corruption_case, detect_archive_format


DEFAULT_OUTPUT_DIR = Path(".sunpack") / "corpus"
DEFAULT_MANIFEST = DEFAULT_OUTPUT_DIR / "repair_plan_manifest.jsonl"
PROFILES = (
    "boundary+directory+payload",
    "header+tail+payload",
    "stream+tail+payload",
    "boundary+sfx+tail",
    "missing_volume+directory+payload",
)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    damaged_dir = output_dir / "damaged"
    manifest_path = Path(args.manifest or output_dir / "repair_plan_manifest.jsonl")
    damaged_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    formats = {item.strip().lower() for item in args.formats.split(",") if item.strip()} if args.formats else set()

    records: list[dict[str, Any]] = []
    sources = _source_archives(input_dir, formats)
    for source_index, source in enumerate(sources):
        fmt = detect_archive_format(source)
        if fmt is None:
            continue
        source_archive_id = _source_archive_id(source)
        for variant_index in range(max(0, int(args.per_source))):
            profile = PROFILES[variant_index % len(PROFILES)]
            case_root = damaged_dir / source_archive_id / f"v{variant_index:03d}"
            try:
                case = build_corpus_corruption_case(
                    case_root,
                    source_path=source,
                    fmt=fmt,
                    seed=int(args.seed) + source_index,
                    variant_index=variant_index,
                    damage_profile=profile,
                )
            except Exception as exc:
                records.append(_skipped_record(source, fmt, source_archive_id, variant_index, profile, exc))
                continue
            records.append(case.corpus_manifest_record(
                source_archive_id=source_archive_id,
                source_path=str(source),
                damage_profile=profile,
                variant_index=variant_index,
            ))

    mode = "a" if args.append else "w"
    with manifest_path.open(mode, encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
    if args.pretty:
        pretty = manifest_path.with_name(manifest_path.name.removesuffix("".join(manifest_path.suffixes)) + ".pretty.json")
        pretty.write_text(json.dumps(records, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")

    print(json.dumps({
        "sources": len(sources),
        "records": len(records),
        "generated": sum(1 for item in records if item.get("damaged_input")),
        "skipped": sum(1 for item in records if item.get("status") == "skipped"),
        "manifest": str(manifest_path),
    }, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a multi-damage repair-plan corpus from clean archives.")
    parser.add_argument("--input-dir", required=True, help="Directory containing clean real/semi-real archives.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Corpus output directory.")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="Manifest JSONL path.")
    parser.add_argument("--per-source", type=int, default=10, help="Damaged variants to derive from each source archive.")
    parser.add_argument("--seed", type=int, default=424242, help="Deterministic corruption seed.")
    parser.add_argument("--formats", default="", help="Optional comma-separated format allowlist.")
    parser.add_argument("--append", action="store_true", help="Append to the manifest instead of replacing it.")
    parser.set_defaults(pretty=True)
    parser.add_argument("--pretty", action="store_true", help="Also write a formatted manifest JSON file. Enabled by default.")
    parser.add_argument("--no-pretty", action="store_false", dest="pretty", help="Only write JSONL.")
    return parser


def _source_archives(input_dir: Path, formats: set[str]) -> list[Path]:
    if not input_dir.is_dir():
        raise SystemExit(f"input directory does not exist: {input_dir}")
    output = []
    for path in sorted(input_dir.rglob("*")):
        if not path.is_file():
            continue
        fmt = detect_archive_format(path)
        if fmt is None:
            continue
        if formats and fmt not in formats:
            continue
        output.append(path)
    return output


def _source_archive_id(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    stem = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in path.stem)[:48]
    return f"{stem}_{digest}"


def _skipped_record(source: Path, fmt: str, source_archive_id: str, variant_index: int, profile: str, exc: Exception) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "skipped",
        "source_archive_id": source_archive_id,
        "source_path": str(source),
        "format": fmt,
        "variant_index": variant_index,
        "damage_profile": profile,
        "error": str(exc),
    }


if __name__ == "__main__":
    raise SystemExit(main())
