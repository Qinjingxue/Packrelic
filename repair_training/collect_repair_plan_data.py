from __future__ import annotations

import argparse
import bz2
import gzip
import json
import lzma
import multiprocessing as mp
import pickle
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sunpack.repair import RepairJob, RepairResult, RepairScheduler
from sunpack.repair.candidate import CandidateSelector, candidate_feature_payload, materialize_candidates


DEFAULT_MANIFEST = Path(".sunpack") / "corpus" / "repair_plan_manifest.jsonl"
DEFAULT_SUCCESS_OUTPUT = Path(".sunpack") / "datasets" / "repair_plan_ltr_success.jsonl"
DEFAULT_FAILURE_OUTPUT = Path(".sunpack") / "datasets" / "repair_plan_ltr_failure.jsonl"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    records = _load_manifest(Path(args.manifest), args.limit)
    success_output = Path(args.success_output)
    failure_output = Path(args.failure_output)
    success_output.parent.mkdir(parents=True, exist_ok=True)
    failure_output.parent.mkdir(parents=True, exist_ok=True)
    success_pretty_records: list[dict[str, Any]] = []
    failure_pretty_records: list[dict[str, Any]] = []
    summary = {
        "samples": 0,
        "success_rows": 0,
        "failure_rows": 0,
        "timeouts": 0,
        "failed": 0,
        "skipped": 0,
        "success_output": str(success_output),
        "failure_output": str(failure_output),
    }
    mode = "a" if args.append else "w"
    with success_output.open(mode, encoding="utf-8") as success_handle, failure_output.open(mode, encoding="utf-8") as failure_handle:
        for record in records:
            if record.get("status") == "skipped":
                summary["skipped"] += 1
                continue
            if args.progress:
                print(f"START {record.get('sample_id')}", flush=True)
            started = time.perf_counter()
            status, rows = _collect_sample_with_timeout(record, args)
            elapsed = round(time.perf_counter() - started, 3)
            for row in rows:
                row["elapsed_sample_seconds"] = elapsed
            is_success = any(int(row.get("label", 0) or 0) > 0 for row in rows)
            target = success_handle if is_success else failure_handle
            for row in rows:
                target.write(json.dumps(row, ensure_ascii=False, sort_keys=True, default=str) + "\n")
            if args.pretty:
                (success_pretty_records if is_success else failure_pretty_records).extend(rows)
            summary["samples"] += 1
            summary["success_rows" if is_success else "failure_rows"] += len(rows)
            summary["timeouts"] += 1 if status == "timeout" else 0
            summary["failed"] += 1 if status == "failed" else 0
            if args.progress:
                print(f"END {record.get('sample_id')} status={status} rows={len(rows)} elapsed={elapsed}s", flush=True)
    if args.pretty:
        _pretty_path(success_output).write_text(json.dumps(success_pretty_records, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
        _pretty_path(failure_output).write_text(json.dumps(failure_pretty_records, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
        summary["success_pretty_output"] = str(_pretty_path(success_output))
        summary["failure_pretty_output"] = str(_pretty_path(failure_output))
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 1 if summary["timeouts"] or summary["failed"] else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect state/action LTR rows from a repair-plan corruption corpus.")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="Repair-plan corpus manifest JSONL.")
    parser.add_argument("--success-output", default=str(DEFAULT_SUCCESS_OUTPUT), help="Rows for samples with useful/complete actions.")
    parser.add_argument("--failure-output", default=str(DEFAULT_FAILURE_OUTPUT), help="Rows for samples without useful actions.")
    parser.add_argument("--append", action="store_true", help="Append instead of overwriting output files.")
    parser.set_defaults(pretty=True)
    parser.add_argument("--pretty", action="store_true", help="Also write formatted .pretty.json files. Enabled by default.")
    parser.add_argument("--no-pretty", action="store_false", dest="pretty", help="Only write compact JSONL.")
    parser.add_argument("--limit", type=int, default=0, help="Collect at most N manifest records.")
    parser.add_argument("--max-rounds", type=int, default=3, help="Maximum repair rounds per damaged sample.")
    parser.add_argument("--beam-size", type=int, default=1, help="Reserved interface for beam collection; v1 advances the top current-system path.")
    parser.add_argument("--max-candidates-per-round", type=int, default=10, help="Maximum candidates logged per round.")
    parser.add_argument("--case-timeout-seconds", type=float, default=45.0, help="Terminate one sample after this timeout. Use 0 to disable.")
    parser.add_argument("--progress", action="store_true", help="Print sample START/END progress.")
    return parser


def _load_manifest(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.is_file():
        raise SystemExit(f"manifest does not exist: {path}")
    records = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
            if limit and len(records) >= limit:
                break
    return records


def _collect_sample_with_timeout(record: dict[str, Any], args: argparse.Namespace) -> tuple[str, list[dict[str, Any]]]:
    timeout = float(args.case_timeout_seconds or 0)
    if timeout <= 0:
        return _collect_sample(record, args)
    with tempfile.TemporaryDirectory(prefix=f"sunpack-plan-worker-{record.get('sample_id', 'sample')}-") as raw_tmp:
        result_path = Path(raw_tmp) / "result.pkl"
        process = mp.Process(target=_collect_worker, args=(record, args, str(result_path)), daemon=True)
        process.start()
        process.join(timeout)
        if process.is_alive():
            process.terminate()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join(5)
            return "timeout", [_terminal_row(record, "timeout", f"sample exceeded {timeout:.1f}s timeout")]
        if result_path.exists():
            with result_path.open("rb") as handle:
                return pickle.load(handle)
        return "failed", [_terminal_row(record, "failed", f"worker exited without result (exitcode={process.exitcode})")]


def _collect_worker(record: dict[str, Any], args: argparse.Namespace, result_path: str) -> None:
    result = _collect_sample(record, args)
    with Path(result_path).open("wb") as handle:
        pickle.dump(result, handle)


def _collect_sample(record: dict[str, Any], args: argparse.Namespace) -> tuple[str, list[dict[str, Any]]]:
    try:
        return "ok", _collect_sample_rows(record, args)
    except Exception as exc:
        return "failed", [_terminal_row(record, "failed", str(exc))]


def _collect_sample_rows(record: dict[str, Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    scheduler = _scheduler()
    selector = CandidateSelector(scheduler.config)
    source_input = dict(record.get("damaged_input") or {})
    fmt = str(record.get("format") or source_input.get("format_hint") or "")
    damage_flags = list(record.get("damage_flags") or [])
    previous_actions: list[str] = []
    rows: list[dict[str, Any]] = []
    best_completeness = 0.0
    for round_index in range(max(1, int(args.max_rounds or 1))):
        job = RepairJob(
            source_input=source_input,
            format=fmt,
            confidence=0.82,
            damage_flags=damage_flags,
            archive_key=f"{record.get('sample_id')}:round:{round_index}",
        )
        batch = scheduler.generate_repair_candidates(job)
        state_features = _state_features(record, batch, round_index, previous_actions, best_completeness)
        candidates = materialize_candidates(list(batch.candidates))
        validated = [selector._with_native_validation(candidate) for candidate in candidates]  # noqa: SLF001
        accepted = sorted(
            [(selector.generation_priority(candidate), index, candidate) for index, candidate in enumerate(validated) if selector._accepted(candidate)],  # noqa: SLF001
            key=lambda item: item[0],
            reverse=True,
        )
        accepted_ids = {_candidate_id(candidate) for _, _, candidate in accepted}
        rejected = [
            (None, index, candidate)
            for index, candidate in enumerate(validated)
            if _candidate_id(candidate) not in accepted_ids
        ]
        ranked = [*accepted, *rejected]
        selected_candidate = accepted[0][2] if accepted else None
        selected_id = _candidate_id(selected_candidate)
        if not validated:
            rows.append(_round_empty_row(record, round_index, state_features, batch))
            break
        logged = 0
        for rank, (_, original_index, candidate) in enumerate(ranked):
            if logged >= int(args.max_candidates_per_round or 0):
                break
            label_info = _label_candidate(record, candidate, best_completeness)
            rows.append(_action_row(
                record,
                round_index,
                original_index,
                rank,
                candidate,
                state_features,
                batch,
                label_info,
                selected=_candidate_id(candidate) == selected_id,
            ))
            logged += 1
        if selected_candidate is None:
            break
        selected_result = selected_candidate.to_result(selection={"selected_module": selected_candidate.module_name})
        if not selected_result.ok or not selected_result.repaired_input:
            break
        selected_label = _label_candidate(record, selected_candidate, best_completeness)
        best_completeness = max(best_completeness, float(selected_label.get("completeness", 0.0) or 0.0))
        previous_actions.extend(str(action) for action in selected_candidate.actions)
        source_input = dict(selected_result.repaired_input)
        damage_flags = list(selected_result.damage_flags or damage_flags)
        if int(selected_label.get("label", 0) or 0) == 3:
            break
    return rows


def _scheduler() -> RepairScheduler:
    return RepairScheduler({
        "repair": {
            "workspace": str(Path(".sunpack") / "repair-plan-workspace"),
            "max_modules_per_job": 64,
            "max_attempts_per_task": 8,
            "stages": {"deep": True},
            "deep": {
                "max_candidates_per_module": 4,
                "verify_candidates": False,
                "max_seconds_per_module": 8.0,
            },
        }
    })


def _state_features(record: dict[str, Any], batch, round_index: int, previous_actions: list[str], best_completeness: float) -> dict[str, Any]:
    diagnosis = batch.diagnosis if isinstance(batch.diagnosis, dict) else {}
    capability = diagnosis.get("capability_decision") if isinstance(diagnosis.get("capability_decision"), dict) else {}
    return {
        "format": record.get("format"),
        "damage_profile": record.get("damage_profile"),
        "damage_flags": list(record.get("damage_flags") or []),
        "corruption_zones": sorted({item.get("zone") for item in record.get("corruption_plan") or [] if item.get("zone")}),
        "corruption_kinds": sorted({item.get("kind") for item in record.get("corruption_plan") or [] if item.get("kind")}),
        "round": round_index,
        "previous_actions": list(previous_actions),
        "previous_action_count": len(previous_actions),
        "best_completeness": float(best_completeness or 0.0),
        "diagnosis": _compact_diagnosis(diagnosis),
        "capability": {
            "selected_modules": list(capability.get("selected_modules") or []),
            "automatic_unrepairable": bool(capability.get("automatic_unrepairable", False)),
        },
    }


def _action_row(
    record: dict[str, Any],
    round_index: int,
    candidate_index: int,
    rank: int,
    candidate,
    state_features: dict[str, Any],
    batch,
    label_info: dict[str, Any],
    *,
    selected: bool,
) -> dict[str, Any]:
    payload = candidate_feature_payload(candidate)
    module_decision = _module_decision(batch, candidate.module_name)
    return {
        "schema_version": 1,
        "source": "repair_plan_corpus",
        "query_id": f"{record.get('sample_id')}:{round_index}",
        "sample_id": record.get("sample_id"),
        "source_archive_id": record.get("source_archive_id"),
        "round": round_index,
        "candidate_index": candidate_index,
        "current_rank": rank,
        "candidate_id": payload.get("candidate_id"),
        "module": candidate.module_name,
        "selected_by_current_system": bool(selected),
        "label": int(label_info.get("label", 0) or 0),
        "label_status": label_info.get("status"),
        "label_details": label_info,
        "stable_features": {
            "state": state_features,
            "candidate": {
                key: payload.get(key)
                for key in (
                    "module",
                    "format",
                    "stage",
                    "status",
                    "actions",
                    "damage_flags",
                    "patch_cost",
                    "risk_penalty",
                    "cost_penalty",
                    "evidence_score",
                    "benefit_score",
                    "native_validation_score",
                    "native_validation_strength",
                    "predicted_completeness",
                    "validation_count",
                    "requires_native_validation",
                    "has_archive_state_plan",
                )
                if key in payload
            },
        },
        "teacher_features": {
            "route_score": module_decision.get("route_score"),
            "fine_score": module_decision.get("fine_score"),
            "module_selected_by_router": module_decision.get("selected"),
            "generation_priority": payload.get("generation_priority"),
            "ranking_raw_score": (payload.get("ltr_features") or {}).get("ranking_raw_score") if isinstance(payload.get("ltr_features"), dict) else None,
            "current_rank": rank,
            "selected_by_current_system": bool(selected),
        },
        "debug_features": {
            "candidate_features": payload,
            "module_decision": module_decision,
        },
    }


def _label_candidate(record: dict[str, Any], candidate, previous_completeness: float) -> dict[str, Any]:
    repaired_input = candidate.repaired_input if isinstance(candidate.repaired_input, dict) else {}
    path = Path(str(repaired_input.get("path") or ""))
    if not path.is_file():
        return {"status": "no_output", "label": 0, "completeness": previous_completeness}
    oracle = record.get("oracle") if isinstance(record.get("oracle"), dict) else {}
    fmt = str(record.get("format") or repaired_input.get("format_hint") or "")
    verified = _verify_output_against_oracle(path, fmt, oracle)
    completeness = float(verified.get("completeness", 0.0) or 0.0)
    if int(verified.get("label", 0) or 0) <= 0 and completeness > previous_completeness + 0.05:
        verified["label"] = 2
        verified["status"] = "state_progress"
    return verified


def _verify_output_against_oracle(path: Path, fmt: str, oracle: dict[str, Any]) -> dict[str, Any]:
    try:
        expected_bytes = oracle.get("expected_bytes") if isinstance(oracle.get("expected_bytes"), dict) else {}
        if expected_bytes:
            digest = _sha256(path.read_bytes())
            complete = digest == expected_bytes.get("sha256")
            return _label_status(3 if complete else -1, "complete" if complete else "hard_negative", 1.0 if complete else 0.0)
        expected_payload = oracle.get("expected_payload") if isinstance(oracle.get("expected_payload"), dict) else {}
        if expected_payload:
            payload = _decompress_payload(path, fmt)
            digest = _sha256(payload)
            complete = digest == expected_payload.get("sha256")
            completeness = len(payload) / max(1, int(expected_payload.get("size") or len(payload) or 1))
            return _label_status(3 if complete else (1 if 0.0 < completeness < 1.0 else -1), "complete" if complete else ("partial" if completeness > 0 else "hard_negative"), completeness)
        expected_files = oracle.get("expected_files") if isinstance(oracle.get("expected_files"), dict) else {}
        if expected_files:
            recovered = _read_archive_hashes(path, fmt)
            matched = sum(1 for name, meta in expected_files.items() if recovered.get(name) == meta.get("sha256"))
            wrong_overlap = any(name in expected_files and recovered[name] != expected_files[name].get("sha256") for name in recovered)
            completeness = matched / max(1, len(expected_files))
            if completeness >= 0.999:
                return {**_label_status(3, "complete", completeness), "matched_files": matched, "expected_files": len(expected_files)}
            if completeness > 0:
                return {**_label_status(1, "partial", completeness), "matched_files": matched, "expected_files": len(expected_files)}
            return {**_label_status(-1 if wrong_overlap else 0, "hard_negative" if wrong_overlap else "no_progress", 0.0), "matched_files": matched, "expected_files": len(expected_files)}
    except Exception as exc:
        return {"status": "hard_negative", "label": -1, "completeness": 0.0, "error": str(exc)}
    return _label_status(0, "no_oracle", 0.0)


def _read_archive_hashes(path: Path, fmt: str) -> dict[str, str]:
    if fmt == "zip":
        with zipfile.ZipFile(path) as archive:
            return {name: _sha256(archive.read(name)) for name in archive.namelist() if not name.endswith("/")}
    if fmt == "tar":
        with tarfile.open(path) as archive:
            output = {}
            for item in archive.getmembers():
                if not item.isfile():
                    continue
                member = archive.extractfile(item)
                if member is not None:
                    output[item.name] = _sha256(member.read())
            return output
    return {}


def _decompress_payload(path: Path, fmt: str) -> bytes:
    raw = path.read_bytes()
    if fmt in {"gzip", "gz", "tar.gz", "tgz"}:
        return gzip.decompress(raw)
    if fmt in {"bzip2", "bz2", "tar.bz2", "tbz2", "tbz"}:
        return bz2.decompress(raw)
    if fmt in {"xz", "tar.xz", "txz"}:
        return lzma.decompress(raw)
    return raw


def _label_status(label: int, status: str, completeness: float) -> dict[str, Any]:
    return {
        "label": int(label),
        "status": status,
        "completeness": max(0.0, min(1.0, float(completeness or 0.0))),
    }


def _round_empty_row(record: dict[str, Any], round_index: int, state_features: dict[str, Any], batch) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": "repair_plan_corpus",
        "query_id": f"{record.get('sample_id')}:{round_index}",
        "sample_id": record.get("sample_id"),
        "round": round_index,
        "candidate_id": None,
        "module": "",
        "selected_by_current_system": False,
        "label": 0,
        "label_status": "no_candidates",
        "stable_features": {"state": state_features, "candidate": {}},
        "teacher_features": {},
        "debug_features": {"warnings": list(batch.warnings or []), "message": batch.message},
    }


def _terminal_row(record: dict[str, Any], status: str, message: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": "repair_plan_corpus",
        "query_id": f"{record.get('sample_id')}:terminal",
        "sample_id": record.get("sample_id"),
        "round": None,
        "candidate_id": None,
        "module": "",
        "selected_by_current_system": False,
        "label": 0,
        "label_status": status,
        "stable_features": {"state": {"format": record.get("format"), "damage_profile": record.get("damage_profile")}, "candidate": {}},
        "teacher_features": {},
        "debug_features": {"message": message},
    }


def _module_decision(batch, module_name: str) -> dict[str, Any]:
    diagnosis = batch.diagnosis if isinstance(batch.diagnosis, dict) else {}
    capability = diagnosis.get("capability_decision") if isinstance(diagnosis.get("capability_decision"), dict) else {}
    for item in capability.get("modules") or []:
        if isinstance(item, dict) and item.get("name") == module_name:
            return dict(item)
    return {}


def _compact_diagnosis(diagnosis: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": diagnosis.get("status"),
        "format": diagnosis.get("format"),
        "confidence": diagnosis.get("confidence"),
        "repairable": diagnosis.get("repairable"),
        "categories": list(diagnosis.get("categories") or []),
        "damage_flags": list(diagnosis.get("damage_flags") or []),
    }


def _candidate_id(candidate) -> str:
    if candidate is None:
        return ""
    return str(candidate_feature_payload(candidate).get("candidate_id") or "")


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _pretty_path(path: Path) -> Path:
    suffix = "".join(path.suffixes)
    if suffix:
        return path.with_name(path.name.removesuffix(suffix) + ".pretty.json")
    return path.with_name(path.name + ".pretty.json")


if __name__ == "__main__":
    raise SystemExit(main())
