import subprocess
import time
from typing import Any

import psutil

from smart_unpacker.contracts.tasks import ArchiveTask


class SevenZipRunner:
    def __init__(self, process_config: dict):
        self.process_config = process_config

    def run_extract_command(
        self,
        cmd: list[str],
        startupinfo,
        runtime_scheduler: Any,
        task: ArchiveTask,
    ) -> subprocess.CompletedProcess:
        if runtime_scheduler is None:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors="replace",
                startupinfo=startupinfo,
                stdin=subprocess.DEVNULL,
            )

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                startupinfo=startupinfo,
                stdin=subprocess.DEVNULL,
            )
        except OSError as exc:
            return subprocess.CompletedProcess(cmd, -100, "", f"7z process failed to start: {exc}")
        stdout, stderr = self.communicate_observed_process(process, runtime_scheduler, task)
        return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)

    def communicate_observed_process(
        self,
        process: subprocess.Popen,
        runtime_scheduler: Any,
        task: ArchiveTask,
    ) -> tuple[str, str]:
        interval = max(0.1, float(self.process_config.get("process_sample_interval_ms", 500) or 500) / 1000.0)
        max_task_seconds = max(0.0, float(self.process_config.get("max_extract_task_seconds", 0) or 0))
        no_progress_timeout = max(0.0, float(self.process_config.get("process_no_progress_timeout_seconds", 0) or 0))
        profile_key = self._task_profile_key(task)
        ps_process = None
        last_io_bytes = 0
        started_at = time.monotonic()
        last_progress_at = started_at
        try:
            ps_process = psutil.Process(process.pid)
            ps_process.cpu_percent(interval=None)
            try:
                io_counters = ps_process.io_counters()
                last_io_bytes = int(io_counters.read_bytes + io_counters.write_bytes)
            except Exception:
                last_io_bytes = 0
        except Exception:
            ps_process = None

        while True:
            try:
                return process.communicate(timeout=interval)
            except subprocess.TimeoutExpired:
                now = time.monotonic()
                if max_task_seconds and now - started_at > max_task_seconds:
                    return self.terminate_observed_process(process, -101, "7z process timed out")
                if ps_process is None:
                    if no_progress_timeout and now - last_progress_at > no_progress_timeout:
                        return self.terminate_observed_process(process, -102, "7z process made no observable progress")
                    continue
                try:
                    cpu_percent = ps_process.cpu_percent(interval=None)
                    memory_bytes = ps_process.memory_info().rss
                    io_counters = ps_process.io_counters()
                    now_io_bytes = int(io_counters.read_bytes + io_counters.write_bytes)
                    io_delta = max(0, now_io_bytes - last_io_bytes)
                    last_io_bytes = now_io_bytes
                    if io_delta > 0 or cpu_percent > 0.1:
                        last_progress_at = now
                    runtime_scheduler.record_process_sample(
                        cpu_percent=cpu_percent,
                        memory_bytes=memory_bytes,
                        io_bytes=io_delta,
                        profile_key=profile_key,
                    )
                    if no_progress_timeout and now - last_progress_at > no_progress_timeout:
                        return self.terminate_observed_process(process, -102, "7z process made no observable progress")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    ps_process = None
                except Exception:
                    continue

    def terminate_observed_process(
        self,
        process: subprocess.Popen,
        returncode: int,
        message: str,
    ) -> tuple[str, str]:
        try:
            process.kill()
        except Exception:
            pass
        try:
            stdout, stderr = process.communicate(timeout=2.0)
        except Exception:
            stdout, stderr = "", ""
        process.returncode = returncode
        return stdout or "", f"{stderr or ''}\n{message}".strip()

    def _task_profile_key(self, task: ArchiveTask) -> str:
        fact_bag = getattr(task, "fact_bag", None)
        if fact_bag is not None and hasattr(fact_bag, "get"):
            profile_key = fact_bag.get("resource.profile_key")
            if profile_key:
                return str(profile_key)
        return "unknown"
