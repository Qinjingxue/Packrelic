import os
import subprocess
import threading
import time

import psutil

from smart_unpacker.extraction.internal.resource_model import ResourceDemand, build_resource_budget, demand_from_value


SCHEDULER_PROFILES = {
    "conservative": {
        "initial_concurrency_limit": 4,
        "poll_interval_ms": 1000,
        "scale_up_threshold_mb_s": 20,
        "scale_up_backlog_threshold_mb_s": 40,
        "scale_down_threshold_mb_s": 140,
        "scale_up_streak_required": 2,
        "scale_down_streak_required": 3,
        "medium_backlog_threshold": 8,
        "high_backlog_threshold": 24,
        "medium_floor_workers": 2,
        "high_floor_workers": 3,
    },
    "aggressive": {
        "initial_concurrency_limit": 6,
        "poll_interval_ms": 500,
        "scale_up_threshold_mb_s": 80,
        "scale_up_backlog_threshold_mb_s": 160,
        "scale_down_threshold_mb_s": 400,
        "scale_up_streak_required": 2,
        "scale_down_streak_required": 3,
        "medium_backlog_threshold": 8,
        "high_backlog_threshold": 24,
        "medium_floor_workers": 4,
        "high_floor_workers": 6,
    },
}


def select_auto_scheduler_profile() -> str:
    cpu_count = os.cpu_count() or 4
    memory_gb = 0.0
    try:
        memory_gb = psutil.virtual_memory().total / (1024**3)
    except Exception:
        memory_gb = 0.0
    if cpu_count >= 12 and memory_gb >= 24:
        return "aggressive"
    return "conservative"


def build_scheduler_profile_config(requested_profile: str | None) -> dict:
    requested_profile = requested_profile or "auto"
    resolved_profile = select_auto_scheduler_profile() if requested_profile == "auto" else requested_profile
    config = dict(SCHEDULER_PROFILES.get(resolved_profile, SCHEDULER_PROFILES["conservative"]))
    config["scheduler_profile"] = requested_profile
    config["resolved_scheduler_profile"] = resolved_profile
    return config


def detect_max_workers() -> int:
    cpu_count = os.cpu_count() or 4
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-PhysicalDisk | Select-Object -Property MediaType"],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
            if "SSD" in result.stdout.upper():
                return max(2, cpu_count)
        except Exception:
            pass
    return 2


def resolve_max_workers() -> int:
    return max(1, detect_max_workers())


class ConcurrencyScheduler:
    def __init__(self, config: dict, current_limit: int = 2, max_workers: int = 8):
        self.config = config
        initial_limit = config.get("initial_concurrency_limit", current_limit)
        self.current_limit = max(1, min(initial_limit, max_workers))
        self.cpu_limit = self.current_limit
        self.io_limit = self.current_limit
        self.memory_limit = self.current_limit
        self.max_workers = max_workers
        self.min_workers = 1
        self.dynamic_floor_workers = 1
        self.base_budget = build_resource_budget(config, max_workers)

        self.is_running = False
        self.active_workers = 0
        self.active_resource_tokens = 0
        self.active_cpu_tokens = 0
        self.active_io_tokens = 0
        self.active_memory_tokens = 0
        self.pending_task_estimate = 0

        self.scale_up_streak = 0
        self.scale_down_streak = 0
        self.cpu_scale_up_streak = 0
        self.cpu_scale_down_streak = 0
        self.io_scale_up_streak = 0
        self.io_scale_down_streak = 0
        self.memory_scale_up_streak = 0
        self.memory_scale_down_streak = 0
        self.io_history = []

        self.cond = threading.Condition()
        self.thread = None

    def start(self):
        self.is_running = True
        self.thread = threading.Thread(target=self._adjust_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=2.0)

    def _adjust_loop(self):
        poll_interval = max(self.config.get("poll_interval_ms", 1000), 100) / 1000.0
        last_io = psutil.disk_io_counters()
        last_bytes = (last_io.read_bytes + last_io.write_bytes) if last_io else 0

        while self.is_running:
            time.sleep(poll_interval)
            now_io = psutil.disk_io_counters()
            if not now_io:
                continue

            now_bytes = now_io.read_bytes + now_io.write_bytes
            delta = now_bytes - last_bytes
            last_bytes = now_bytes
            try:
                cpu_percent = psutil.cpu_percent(interval=None)
            except Exception:
                cpu_percent = None
            try:
                available_memory = psutil.virtual_memory().available
            except Exception:
                available_memory = None

            self.io_history.append(delta)
            if len(self.io_history) > 5:
                self.io_history.pop(0)

            avg_delta = sum(self.io_history) / len(self.io_history)
            self.adjust_once(avg_delta, cpu_percent=cpu_percent, available_memory=available_memory)

    def adjust_once(self, avg_delta: float, cpu_percent: float | None = None, available_memory: int | None = None):
        scale_up_threshold = self.config.get("scale_up_threshold_mb_s", 50) * 1024 * 1024
        scale_up_backlog_threshold = self.config.get(
            "scale_up_backlog_threshold_mb_s",
            self.config.get("scale_up_threshold_mb_s", 50) * 2,
        ) * 1024 * 1024
        scale_down_threshold = self.config.get("scale_down_threshold_mb_s", 200) * 1024 * 1024
        cpu_scale_up_threshold = self.config.get("cpu_scale_up_threshold_percent", 65)
        cpu_scale_down_threshold = self.config.get("cpu_scale_down_threshold_percent", 88)
        memory_scale_down_available = self.config.get("memory_scale_down_available_mb", 1024) * 1024 * 1024
        memory_scale_up_available = self.config.get("memory_scale_up_available_mb", 2048) * 1024 * 1024
        scale_up_streak_req = max(1, self.config.get("scale_up_streak_required", 3))
        scale_down_streak_req = max(1, self.config.get("scale_down_streak_required", 2))
        medium_backlog_threshold = max(1, self.config.get("medium_backlog_threshold", 8))
        high_backlog_threshold = max(medium_backlog_threshold, self.config.get("high_backlog_threshold", 24))
        medium_floor_workers = max(1, self.config.get("medium_floor_workers", 2))
        high_floor_workers = max(medium_floor_workers, self.config.get("high_floor_workers", 3))

        with self.cond:
            backlog = self.pending_task_estimate
            if self.max_workers <= 1:
                dynamic_floor = 1
            elif backlog >= max(high_backlog_threshold, self.max_workers * 4) and self.max_workers >= 4:
                dynamic_floor = min(high_floor_workers, self.max_workers)
            elif backlog >= max(medium_backlog_threshold, self.max_workers * 2):
                dynamic_floor = min(medium_floor_workers, self.max_workers)
            else:
                dynamic_floor = self.min_workers
            self.dynamic_floor_workers = dynamic_floor

            old_limits = (self.cpu_limit, self.io_limit, self.memory_limit, self.current_limit)
            backlog_wants_more = backlog > max(self.cpu_limit, self.io_limit, self.memory_limit) * 2

            self._adjust_cpu_limit_locked(
                cpu_percent,
                backlog_wants_more,
                dynamic_floor,
                scale_up_streak_req,
                scale_down_streak_req,
                cpu_scale_up_threshold,
                cpu_scale_down_threshold,
            )
            self._adjust_io_limit_locked(
                avg_delta,
                backlog,
                dynamic_floor,
                scale_up_threshold,
                scale_up_backlog_threshold,
                scale_down_threshold,
                scale_up_streak_req,
                scale_down_streak_req,
            )
            self._adjust_memory_limit_locked(
                available_memory,
                backlog_wants_more,
                dynamic_floor,
                scale_up_streak_req,
                scale_down_streak_req,
                memory_scale_down_available,
                memory_scale_up_available,
            )
            self._refresh_current_limit_locked()
            if old_limits != (self.cpu_limit, self.io_limit, self.memory_limit, self.current_limit):
                self.cond.notify_all()

    def update_pending_task_estimate(self, pending_count: int, futures_count: int = 0):
        with self.cond:
            self.pending_task_estimate = pending_count + futures_count + self.active_workers

    def acquire_slot(self, token_cost: int = 1, demand: ResourceDemand | dict | None = None):
        demand_value = demand_from_value(demand or token_cost)
        with self.cond:
            while not self._can_acquire_locked(demand_value):
                self.cond.wait()
            self.active_workers += 1
            self._add_demand_locked(demand_value)

    def try_acquire_slot(self, token_cost: int = 1, demand: ResourceDemand | dict | None = None) -> bool:
        demand_value = demand_from_value(demand or token_cost)
        with self.cond:
            if not self._can_acquire_locked(demand_value):
                return False
            self.active_workers += 1
            self._add_demand_locked(demand_value)
            return True

    def release_slot(self, token_cost: int = 1, demand: ResourceDemand | dict | None = None):
        demand_value = demand_from_value(demand or token_cost)
        with self.cond:
            self.active_workers = max(0, self.active_workers - 1)
            self.active_cpu_tokens = max(0, self.active_cpu_tokens - demand_value.cpu)
            self.active_io_tokens = max(0, self.active_io_tokens - demand_value.io)
            self.active_memory_tokens = max(0, self.active_memory_tokens - demand_value.memory)
            self._refresh_active_scalar_locked()
            self.cond.notify_all()

    def _effective_budget_locked(self):
        normalized = self.base_budget.normalized()
        return type(normalized)(
            cpu=max(1, min(normalized.cpu, self.cpu_limit)),
            io=max(1, min(normalized.io, self.io_limit)),
            memory=max(1, min(normalized.memory, self.memory_limit)),
        )

    def _can_acquire_locked(self, demand: ResourceDemand) -> bool:
        demand = demand.normalized()
        budget = self._effective_budget_locked()
        if self.active_workers <= 0:
            return True
        if self.active_workers >= self.max_workers:
            return False
        return (
            self.active_cpu_tokens + demand.cpu <= budget.cpu
            and self.active_io_tokens + demand.io <= budget.io
            and self.active_memory_tokens + demand.memory <= budget.memory
        )

    def _add_demand_locked(self, demand: ResourceDemand) -> None:
        demand = demand.normalized()
        self.active_cpu_tokens += demand.cpu
        self.active_io_tokens += demand.io
        self.active_memory_tokens += demand.memory
        self._refresh_active_scalar_locked()

    def _refresh_active_scalar_locked(self) -> None:
        self.active_resource_tokens = max(
            self.active_cpu_tokens,
            self.active_io_tokens,
            self.active_memory_tokens,
        )

    def _adjust_cpu_limit_locked(
        self,
        cpu_percent: float | None,
        backlog_wants_more: bool,
        dynamic_floor: int,
        scale_up_streak_req: int,
        scale_down_streak_req: int,
        scale_up_threshold: float,
        scale_down_threshold: float,
    ) -> None:
        if cpu_percent is None:
            self.cpu_limit = max(dynamic_floor, min(self.cpu_limit, self.max_workers))
            return
        near_capacity = self.active_cpu_tokens >= max(1, self.cpu_limit - 1)
        if backlog_wants_more and cpu_percent < scale_up_threshold:
            self.cpu_scale_up_streak += 1
            self.cpu_scale_down_streak = 0
        elif cpu_percent > scale_down_threshold and near_capacity:
            self.cpu_scale_down_streak += 1
            self.cpu_scale_up_streak = 0
        else:
            self.cpu_scale_up_streak = 0
            self.cpu_scale_down_streak = 0

        if self.cpu_scale_up_streak >= scale_up_streak_req and self.cpu_limit < self.max_workers:
            self.cpu_limit = min(self.max_workers, self.cpu_limit + 1)
            self.cpu_scale_up_streak = 0
        elif self.cpu_scale_down_streak >= scale_down_streak_req and self.cpu_limit > dynamic_floor:
            self.cpu_limit = max(dynamic_floor, self.cpu_limit - 1)
            self.cpu_scale_down_streak = 0
        self.cpu_limit = max(dynamic_floor, min(self.cpu_limit, self.max_workers))

    def _adjust_io_limit_locked(
        self,
        avg_delta: float,
        backlog: int,
        dynamic_floor: int,
        scale_up_threshold: float,
        scale_up_backlog_threshold: float,
        scale_down_threshold: float,
        scale_up_streak_req: int,
        scale_down_streak_req: int,
    ) -> None:
        near_capacity = self.active_io_tokens >= max(1, self.io_limit - 1)
        if avg_delta < scale_up_threshold or (backlog > self.io_limit * 2 and avg_delta < scale_up_backlog_threshold):
            self.io_scale_up_streak += 1
            self.io_scale_down_streak = 0
            self.scale_up_streak = self.io_scale_up_streak
            self.scale_down_streak = 0
        elif avg_delta > scale_down_threshold and near_capacity and backlog <= self.io_limit * 4:
            self.io_scale_down_streak += 1
            self.io_scale_up_streak = 0
            self.scale_down_streak = self.io_scale_down_streak
            self.scale_up_streak = 0
        else:
            self.io_scale_up_streak = 0
            self.io_scale_down_streak = 0
            self.scale_up_streak = 0
            self.scale_down_streak = 0

        if self.io_scale_up_streak >= scale_up_streak_req and self.io_limit < self.max_workers:
            step = 2 if backlog >= self.io_limit * 4 and avg_delta < scale_up_threshold else 1
            self.io_limit = min(self.max_workers, self.io_limit + step)
            self.io_scale_up_streak = 0
            self.scale_up_streak = 0
        elif self.io_scale_down_streak >= scale_down_streak_req and self.io_limit > dynamic_floor:
            self.io_limit = max(dynamic_floor, self.io_limit - 1)
            self.io_scale_down_streak = 0
            self.scale_down_streak = 0
        self.io_limit = max(dynamic_floor, min(self.io_limit, self.max_workers))

    def _adjust_memory_limit_locked(
        self,
        available_memory: int | None,
        backlog_wants_more: bool,
        dynamic_floor: int,
        scale_up_streak_req: int,
        scale_down_streak_req: int,
        scale_down_available: int,
        scale_up_available: int,
    ) -> None:
        if available_memory is None:
            self.memory_limit = max(dynamic_floor, min(self.memory_limit, self.max_workers))
            return
        memory_floor = self.min_workers if available_memory < scale_down_available else dynamic_floor
        near_capacity = self.active_memory_tokens >= max(1, self.memory_limit - 1)
        if backlog_wants_more and available_memory > scale_up_available:
            self.memory_scale_up_streak += 1
            self.memory_scale_down_streak = 0
        elif available_memory < scale_down_available and near_capacity:
            self.memory_scale_down_streak += 1
            self.memory_scale_up_streak = 0
        else:
            self.memory_scale_up_streak = 0
            self.memory_scale_down_streak = 0

        if self.memory_scale_up_streak >= scale_up_streak_req and self.memory_limit < self.max_workers:
            self.memory_limit = min(self.max_workers, self.memory_limit + 1)
            self.memory_scale_up_streak = 0
        elif self.memory_scale_down_streak >= scale_down_streak_req and self.memory_limit > memory_floor:
            self.memory_limit = max(memory_floor, self.memory_limit - 1)
            self.memory_scale_down_streak = 0
        self.memory_limit = max(memory_floor, min(self.memory_limit, self.max_workers))

    def _refresh_current_limit_locked(self) -> None:
        self.current_limit = max(1, min(self.max_workers, max(self.cpu_limit, self.io_limit, self.memory_limit)))
