from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.coordinator.scheduling.resource_model import build_resource_profile_key, estimate_resource_demand
from smart_unpacker.passwords import PasswordSession
from smart_unpacker.rename.scheduler import RenameScheduler
from smart_unpacker.support.sevenzip_native import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_UNSUPPORTED,
    cached_analyze_archive_resources,
)


class ResourcePreflightInspector:
    def __init__(
        self,
        password_session: PasswordSession | None = None,
        rename_scheduler: RenameScheduler | None = None,
    ):
        self.password_session = password_session
        self.rename_scheduler = rename_scheduler or RenameScheduler()

    def inspect(self, task: ArchiveTask) -> ArchiveTask:
        health = task.fact_bag.get("resource.health") or {}
        if health.get("status") in {STATUS_BACKEND_UNAVAILABLE, STATUS_UNSUPPORTED}:
            return self._record_unknown(task)

        staged = self.rename_scheduler.normalize_archive_paths(task.main_path, list(task.all_parts or [task.main_path]))
        try:
            password = self._password_for(task)
            analysis = cached_analyze_archive_resources(staged.archive, password=password, part_paths=staged.run_parts)
            self._record_analysis(task, analysis)
            demand = estimate_resource_demand(analysis)
            task.fact_bag.set("resource.tokens", demand.as_dict())
            task.fact_bag.set("resource.token_cost", demand.scalar_cost)
            task.fact_bag.set("resource.profile_key", build_resource_profile_key(analysis))
        finally:
            self.rename_scheduler.cleanup_normalized_split_group(staged)
        return task

    def _password_for(self, task: ArchiveTask) -> str:
        if self.password_session is None:
            return ""
        return self.password_session.get_resolved(task.key) or ""

    def _record_unknown(self, task: ArchiveTask) -> ArchiveTask:
        task.fact_bag.set("resource.tokens", {"cpu": 1, "io": 1, "memory": 1})
        task.fact_bag.set("resource.token_cost", 1)
        task.fact_bag.set("resource.profile_key", "unknown")
        return task

    def _record_analysis(self, task: ArchiveTask, analysis) -> None:
        task.fact_bag.set("resource.analysis", {
            "status": analysis.status,
            "is_archive": analysis.is_archive,
            "is_encrypted": analysis.is_encrypted,
            "is_broken": analysis.is_broken,
            "solid": analysis.solid,
            "item_count": analysis.item_count,
            "file_count": analysis.file_count,
            "dir_count": analysis.dir_count,
            "archive_size": analysis.archive_size,
            "total_unpacked_size": analysis.total_unpacked_size,
            "total_packed_size": analysis.total_packed_size,
            "largest_item_size": analysis.largest_item_size,
            "largest_dictionary_size": analysis.largest_dictionary_size,
            "archive_type": analysis.archive_type,
            "dominant_method": analysis.dominant_method,
            "message": analysis.message,
        })
