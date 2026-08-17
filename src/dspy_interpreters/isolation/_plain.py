"""Portable, unconfined worker backend.

``PlainBackend`` runs the worker as an ordinary child process on any operating
system.  It provides only what a plain process can honestly provide: its own
address space, the host wall-time deadline, death with the host, an explicit
environment, and (where the operating system enforces them) rlimit / job-object
resource caps.  It never provides filesystem, network, or kernel-surface
confinement; those need the platform backends.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Any

from dspy_interpreters.isolation._backend import (
    BackendCapabilities,
    LaunchPlan,
    base_policy,
    clean_env,
    inherited_env,
    python_argv,
    refuse_unmet,
    session_paths,
    universal_guarantees,
)
from dspy_interpreters.isolation.spec import (
    CLEAN_ENVIRONMENT,
    CPU_TIME_CAPPED,
    FILESYSTEM_ALLOWLIST,
    KILLED_WITH_HOST,
    MEMORY_CAPPED,
    NO_AMBIENT_NETWORK,
    NO_NEW_PRIVILEGES,
    OWN_ADDRESS_SPACE,
    PRIVATE_TMP,
    PROCESS_COUNT_CAPPED,
    REDUCED_KERNEL_SURFACE,
    WALL_TIME_CAPPED,
    IsolationReport,
    IsolationSpec,
)

_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_NO_WINDOW = 0x08000000

_NO_FILESYSTEM_POLICY = "plain backend has no filesystem policy"
_REAPER_NOTE = (
    "killed_with_host ends the worker process itself; a helper forked by the worker then SIGKILLs the worker's "
    "process group, so guest processes survive only if they left the session (setsid)"
)


def _job_object_class() -> Any | None:
    """The Windows ``JobObject`` helper when it is importable and usable, else ``None``."""
    try:
        from dspy_interpreters.isolation._windows import JobObject
    except Exception:
        return None
    try:
        return JobObject if JobObject.available() else None
    except Exception:
        return None


class PlainBackend:
    """Any-OS worker process without operating-system confinement."""

    name = "plain"

    def __init__(self, platform: str = sys.platform) -> None:
        self.platform = platform
        self._capabilities: BackendCapabilities | None = None

    # -- probe --------------------------------------------------------------- #

    @property
    def _is_windows(self) -> bool:
        return self.platform == "win32"

    @property
    def _is_linux(self) -> bool:
        return self.platform.startswith("linux")

    def _job_available(self) -> bool:
        return self._is_windows and _job_object_class() is not None

    def capabilities(self) -> BackendCapabilities:
        if self._capabilities is not None:
            return self._capabilities
        supported: dict[str, str] = {
            OWN_ADDRESS_SPACE: "separate worker process",
            WALL_TIME_CAPPED: "host deadline kills the worker",
            CLEAN_ENVIRONMENT: "explicit environment + python -I",
        }
        unsupported: dict[str, str] = {
            FILESYSTEM_ALLOWLIST: _NO_FILESYSTEM_POLICY + "; request it through the platform backend",
            PRIVATE_TMP: _NO_FILESYSTEM_POLICY,
            NO_AMBIENT_NETWORK: "plain backend cannot remove network access; request it through the platform backend",
            NO_NEW_PRIVILEGES: "plain backend does not apply PR_SET_NO_NEW_PRIVS; request it through the Linux backend",
            REDUCED_KERNEL_SURFACE: "plain backend installs no seccomp filter; request it through the Linux backend",
        }
        notes: list[str] = ["plain backend: no filesystem or network confinement"]
        if self._is_windows:
            if self._job_available():
                supported[KILLED_WITH_HOST] = "job object KILL_ON_JOB_CLOSE"
                supported[MEMORY_CAPPED] = "job object ProcessMemoryLimit"
                supported[CPU_TIME_CAPPED] = "job object PerProcessUserTimeLimit"
                supported[PROCESS_COUNT_CAPPED] = "job object ActiveProcessLimit"
            else:
                supported[KILLED_WITH_HOST] = "ppid watchdog"
                reason = "Windows job objects unavailable (kernel32 or the Windows backend could not be loaded)"
                unsupported[MEMORY_CAPPED] = reason
                unsupported[CPU_TIME_CAPPED] = reason
                unsupported[PROCESS_COUNT_CAPPED] = reason
        else:
            supported[KILLED_WITH_HOST] = "PR_SET_PDEATHSIG" if self._is_linux else "ppid watchdog"
            supported[CPU_TIME_CAPPED] = "RLIMIT_CPU"
            supported[PROCESS_COUNT_CAPPED] = "RLIMIT_NPROC (counts every process of the user)"
            if self._is_linux:
                supported[MEMORY_CAPPED] = "RLIMIT_AS"
            elif self.platform == "darwin":
                unsupported[MEMORY_CAPPED] = "macOS does not enforce RLIMIT_AS; no cgroup equivalent"
            else:
                unsupported[MEMORY_CAPPED] = f"RLIMIT_AS enforcement is not verified on {self.platform}"
        self._capabilities = BackendCapabilities(
            name=self.name,
            platform=self.platform,
            supported=supported,
            unsupported=unsupported,
            notes=tuple(notes),
        )
        return self._capabilities

    # -- plan ---------------------------------------------------------------- #

    def plan(self, spec: IsolationSpec, *, python: str, worker_path: str, session_dir: str) -> LaunchPlan:
        capabilities = self.capabilities()
        refuse_unmet(spec, capabilities)
        paths = session_paths(session_dir)
        work_dir = paths["work"]
        tmp_dir = paths["tmp"]

        if spec.env.mode == "clean":
            env = clean_env(spec, tmp_dir=tmp_dir, work_dir=work_dir, platform=self.platform)
        else:
            env = inherited_env(spec, tmp_dir=tmp_dir)
        argv = python_argv(python, worker_path, spec)
        policy = base_policy(spec, work_dir=work_dir)

        limits = spec.limits
        guarantees = universal_guarantees(spec)
        guarantees[KILLED_WITH_HOST] = capabilities.supported[KILLED_WITH_HOST]
        if spec.env.mode == "clean":
            guarantees[CLEAN_ENVIRONMENT] = capabilities.supported[CLEAN_ENVIRONMENT]
        required: list[str] = []
        popen_kwargs: dict[str, Any] = {}
        state: dict[str, Any] = {}
        notes = list(capabilities.notes)
        if not self._is_windows:
            notes.append(_REAPER_NOTE)

        if self._is_windows:
            policy["rlimits"] = {}  # no ``resource`` module on Windows
            popen_kwargs["creationflags"] = _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW
            if self._job_available():
                state["job_limits"] = {
                    "memory_bytes": limits.memory_bytes,
                    "cpu_seconds": limits.cpu_seconds,
                    "max_processes": limits.max_processes,
                }
                for guarantee, wanted in (
                    (MEMORY_CAPPED, limits.memory is not None),
                    (CPU_TIME_CAPPED, limits.cpu_seconds is not None),
                    (PROCESS_COUNT_CAPPED, limits.max_processes is not None),
                ):
                    if wanted:
                        guarantees[guarantee] = capabilities.supported[guarantee]
            else:
                required.append("ppid_watchdog")
        else:
            popen_kwargs["start_new_session"] = True
            policy["pgroup_reaper"] = True  # the worker owns its session: a helper may killpg the group
            required.append("pdeathsig" if self._is_linux else "ppid_watchdog")
            rlimits = policy["rlimits"]
            if limits.cpu_seconds is not None:
                required.append("rlimit:cpu")
                guarantees[CPU_TIME_CAPPED] = capabilities.supported[CPU_TIME_CAPPED]
            if limits.max_processes is not None:
                rlimits["nproc"] = int(limits.max_processes)
                required.append("rlimit:nproc")
                guarantees[PROCESS_COUNT_CAPPED] = capabilities.supported[PROCESS_COUNT_CAPPED]
            if limits.memory is not None:
                # Only Linux enforces RLIMIT_AS; capabilities() already refused the request elsewhere.
                rlimits["as"] = int(limits.memory_bytes or 0)
                required.append("rlimit:as")
                guarantees[MEMORY_CAPPED] = capabilities.supported[MEMORY_CAPPED]

        report = IsolationReport(
            backend=self.name,
            platform=self.platform,
            requested=spec.guarantees(),
            guarantees=guarantees,
            notes=tuple(notes),
        )
        return LaunchPlan(
            argv=argv,
            env=env,
            cwd=work_dir,
            policy=policy,
            report=report,
            popen_kwargs=popen_kwargs,
            required_applied=tuple(required),
            state=state,
        )

    # -- process hooks ------------------------------------------------------- #

    def attach(self, process: subprocess.Popen[bytes], plan: LaunchPlan) -> None:
        job_limits = plan.state.get("job_limits")
        if job_limits is None:
            return
        job_class = _job_object_class()
        if job_class is None:
            raise RuntimeError("Windows job objects are unavailable")
        job = job_class.create(
            memory_bytes=job_limits.get("memory_bytes"),
            cpu_seconds=job_limits.get("cpu_seconds"),
            max_processes=job_limits.get("max_processes"),
            kill_on_close=True,
            ui_restrictions=True,
        )
        plan.state["job"] = job
        job.assign(process)

    def kill(self, process: subprocess.Popen[bytes], plan: LaunchPlan) -> None:
        job = plan.state.pop("job", None)
        if job is not None:
            try:
                job.terminate(1)
            except Exception:
                pass
        if not self._is_windows and hasattr(os, "killpg"):
            import signal

            try:
                os.killpg(process.pid, signal.SIGKILL)
            except Exception:
                pass
        try:
            process.kill()
        except Exception:
            pass
        if job is not None:
            try:
                job.close()
            except Exception:
                pass


__all__ = ["PlainBackend"]
