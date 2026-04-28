from dataclasses import replace
from pathlib import Path
from typing import Any

from smart_unpacker.repair.candidate import CandidateSelector, RepairCandidate
from smart_unpacker.repair.config import enabled_module_configs, repair_config
from smart_unpacker.repair.context import RepairContext, build_repair_context
from smart_unpacker.repair.diagnosis import RepairDiagnosis, diagnose_repair_job
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairRoute
from smart_unpacker.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry
from smart_unpacker.repair.result import RepairResult


class RepairScheduler:
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = repair_config(config or {})
        discover_repair_modules()

    def diagnose(self, job: RepairJob) -> RepairDiagnosis:
        return diagnose_repair_job(job)

    def repair(self, job: RepairJob) -> RepairResult:
        diagnosis = self.diagnose(job)
        context = build_repair_context(job, diagnosis)
        if not self.config.get("enabled", True):
            return self._result("skipped", job, diagnosis, "repair layer is disabled")
        if not diagnosis.repairable:
            return self._result("unrepairable", job, diagnosis, "; ".join(diagnosis.notes) or "repair is blocked")

        modules = self._select_modules(job, diagnosis, context)
        if not modules:
            return self._result("unsupported", job, diagnosis, "no repair module is registered for this diagnosis")

        workspace = self._workspace_for(job)
        workspace.mkdir(parents=True, exist_ok=True)
        module_configs = enabled_module_configs(self.config)
        selector = CandidateSelector(self.config)
        warnings = []
        repair_candidates: list[RepairCandidate] = []
        for score, module, route_score in modules:
            module_config = self._module_runtime_config(module.spec.name, module_configs)
            try:
                if hasattr(module, "generate_candidates"):
                    generated = module.generate_candidates(  # type: ignore[attr-defined]
                        job,
                        diagnosis,
                        str(workspace),
                        module_config,
                    )
                    if not generated:
                        warnings.append(f"{module.spec.name}: produced no repair candidates")
                        continue
                    for candidate in generated:
                        repair_candidates.append(replace(
                            candidate,
                            score_hint=max(score, route_score, candidate.score_hint),
                            stage=candidate.stage or module.spec.stage,
                        ))
                    continue

                result = module.repair(job, diagnosis, str(workspace), module_config)
            except Exception as exc:
                warnings.append(f"{module.spec.name}: {exc}")
                continue
            if result.ok:
                candidate = RepairCandidate.from_result(
                    result,
                    score_hint=max(score, route_score),
                    stage=module.spec.stage,
                )
                if candidate is not None:
                    repair_candidates.append(candidate)
                continue
            warnings.extend(result.warnings)
        if repair_candidates:
            selected, selection = selector.select(repair_candidates)
            if selected is not None:
                return selected.to_result(selection=selection)
            warnings.extend(selection.get("warnings") or [])
            warnings.append("repair candidates were produced but none passed selection")
        return RepairResult(
            status="unrepairable",
            confidence=diagnosis.confidence,
            format=diagnosis.format,
            warnings=_dedupe(warnings),
            diagnosis=diagnosis.as_dict(),
            message="registered repair modules did not produce a candidate",
        )

    def _select_modules(self, job: RepairJob, diagnosis: RepairDiagnosis, context: RepairContext):
        enabled = enabled_module_configs(self.config)
        registry = get_repair_module_registry()
        candidates = []
        for name, module in registry.all().items():
            if name not in enabled:
                continue
            route_score = self._route_score(module.spec.routes, context)
            if route_score <= 0 and diagnosis.format not in module.spec.formats and "archive" not in module.spec.formats:
                continue
            if route_score <= 0 and module.spec.categories and not (set(module.spec.categories) & set(diagnosis.categories)):
                continue
            stages = self.config.get("stages", {}) if isinstance(self.config.get("stages"), dict) else {}
            if not stages.get(module.spec.stage, True):
                continue
            module_config = self._module_runtime_config(name, enabled)
            if not self._safety_allows(module, module_config):
                continue
            if module.spec.stage == "deep" and not self._deep_input_allowed(job, module_config):
                continue
            fine_score = float(module.can_handle(job, diagnosis, module_config) or 0.0)
            score = max(fine_score, route_score)
            if score <= 0:
                continue
            candidates.append((score, module, route_score))
        candidates.sort(key=lambda item: item[0], reverse=True)
        limit = max(1, int(self.config.get("max_modules_per_job", 4) or 4))
        return candidates[:limit]

    def _route_score(self, routes: tuple[RepairRoute, ...], context: RepairContext) -> float:
        best = 0.0
        for route in routes:
            score = self._single_route_score(route, context)
            if score > best:
                best = score
        return best

    def _single_route_score(self, route: RepairRoute, context: RepairContext) -> float:
        if route.formats and not _format_matches(context.format, route.formats):
            return 0.0
        if _intersects(route.reject_any_flags, context.damage_flags):
            return 0.0
        if context.failure_stage and _intersects(route.reject_any_failure_stages, (context.failure_stage,)):
            return 0.0
        if context.failure_kind and _intersects(route.reject_any_failure_kinds, (context.failure_kind,)):
            return 0.0

        score = float(route.base_score or 0.0)
        requirements = [
            (route.require_any_categories, context.categories, 0.08),
            (route.require_any_flags, context.damage_flags, 0.12),
            (route.require_any_fuzzy_hints, context.fuzzy_hints, 0.08),
            (route.require_any_failure_stages, (context.failure_stage,), 0.1),
            (route.require_any_failure_kinds, (context.failure_kind,), 0.14),
        ]
        active_requirements = [item for item in requirements if item[0]]
        if not active_requirements:
            return max(0.0, min(score, 1.0))
        matched = False
        for expected, actual, bonus in active_requirements:
            if _intersects(expected, actual):
                matched = True
                score += bonus
        if not matched:
            return 0.0
        return max(0.0, min(score, 1.0))

    def _safety_allows(self, module, module_config: dict[str, Any]) -> bool:
        safety = module_config.get("safety") if isinstance(module_config.get("safety"), dict) else {}
        if not bool(safety.get("allow_unsafe", False)) and not module.spec.safe:
            return False
        if not bool(safety.get("allow_partial", True)) and module.spec.partial:
            return False
        if not bool(safety.get("allow_lossy", False)) and module.spec.lossy:
            return False
        return True

    def _deep_input_allowed(self, job: RepairJob, module_config: dict[str, Any]) -> bool:
        deep = module_config.get("deep") if isinstance(module_config.get("deep"), dict) else {}
        max_mb = float(deep.get("max_input_size_mb", 0) or 0)
        if max_mb <= 0:
            return True
        size = _source_input_size(job.source_input)
        if size is None:
            return True
        return size <= int(max_mb * 1024 * 1024)

    def _module_runtime_config(self, name: str, module_configs: dict[str, dict[str, Any]]) -> dict[str, Any]:
        config = dict(module_configs.get(name, {}))
        safety = dict(self.config.get("safety") or {})
        if isinstance(config.get("safety"), dict):
            safety.update(config["safety"])
        deep = dict(self.config.get("deep") or {})
        if isinstance(config.get("deep"), dict):
            deep.update(config["deep"])
        config["safety"] = safety
        config["deep"] = deep
        return config

    def _workspace_for(self, job: RepairJob) -> Path:
        base = Path(job.workspace or self.config.get("workspace") or ".smart_unpacker_repair")
        key = _safe_key(job.archive_key or str(job.source_input.get("path") or job.source_input.get("archive_path") or "archive"))
        return base / key

    def _result(self, status: str, job: RepairJob, diagnosis: RepairDiagnosis, message: str) -> RepairResult:
        return RepairResult(
            status=status,
            confidence=diagnosis.confidence,
            format=diagnosis.format or job.format,
            damage_flags=list(job.damage_flags),
            diagnosis=diagnosis.as_dict(),
            message=message,
        )


def _safe_key(value: str) -> str:
    text = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(value or "archive"))
    return text[-120:] or "archive"


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _source_input_size(source_input: dict[str, Any]) -> int | None:
    kind = str(source_input.get("kind") or "file")
    if kind == "file":
        return _path_size(source_input.get("path"))
    if kind == "file_range":
        return _range_size(source_input)
    if kind == "concat_ranges":
        total = 0
        for item in source_input.get("ranges") or []:
            if not isinstance(item, dict):
                return None
            size = _range_size(item)
            if size is None:
                return None
            total += size
        return total
    return None


def _range_size(item: dict[str, Any]) -> int | None:
    start = int(item.get("start") or 0)
    end = item.get("end")
    if end is not None:
        return max(0, int(end) - start)
    size = _path_size(item.get("path"))
    if size is None:
        return None
    return max(0, size - start)


def _path_size(path: Any) -> int | None:
    try:
        return Path(str(path)).stat().st_size
    except (OSError, TypeError, ValueError):
        return None


def _intersects(left, right) -> bool:
    return bool({str(item).lower() for item in left} & {str(item).lower() for item in right if str(item or "")})


def _format_matches(fmt: str, expected) -> bool:
    normalized = _normalize_format(fmt)
    formats = {_normalize_format(item) for item in expected}
    return normalized in formats or "archive" in formats


def _normalize_format(value: Any) -> str:
    text = str(value or "").lower().lstrip(".")
    aliases = {
        "seven_zip": "7z",
        "sevenzip": "7z",
        "gz": "gzip",
        "bz2": "bzip2",
        "zst": "zstd",
        "tgz": "tar.gz",
        "tbz2": "tar.bz2",
        "txz": "tar.xz",
    }
    return aliases.get(text, text or "unknown")
