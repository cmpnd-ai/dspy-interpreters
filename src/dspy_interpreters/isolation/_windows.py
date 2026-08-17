"""Windows backend: a Job Object caps memory, CPU time, and process count and kills the tree with the host.

Everything here is plain ``ctypes`` so the module imports on every operating
system; ``kernel32`` is loaded lazily and only when a job is actually created.
``job_limits`` is a pure function that computes the limit flags and fields for
tests and for the plain backend.

Not provided (refused loudly): filesystem_allowlist and no_ambient_network
(these need AppContainer/ACL confinement), no_new_privileges, and
reduced_kernel_surface.
"""

from __future__ import annotations

import ctypes
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

BACKEND_NAME = "windows-job-object"

# Win32 type aliases (64-bit and 32-bit correct).
LARGE_INTEGER = ctypes.c_int64
DWORD = ctypes.c_uint32
SIZE_T = ctypes.c_size_t
ULONG_PTR = ctypes.c_size_t
ULONGLONG = ctypes.c_uint64
HANDLE = ctypes.c_void_p
BOOL = ctypes.c_int
UINT = ctypes.c_uint32

# JOBOBJECTINFOCLASS
JobObjectBasicUIRestrictions = 4
JobObjectExtendedLimitInformation = 9

# JOB_OBJECT_LIMIT_* flags
JOB_OBJECT_LIMIT_PROCESS_TIME = 0x2
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x8
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x400
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000

# JOB_OBJECT_UILIMIT_* (all eight bits)
JOB_OBJECT_UILIMIT_ALL = 0xFF

# Process creation flags
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
CREATE_BREAKAWAY_FROM_JOB = 0x01000000

_HUNDRED_NS_PER_SECOND = 10_000_000


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ULONGLONG),
        ("WriteOperationCount", ULONGLONG),
        ("OtherOperationCount", ULONGLONG),
        ("ReadTransferCount", ULONGLONG),
        ("WriteTransferCount", ULONGLONG),
        ("OtherTransferCount", ULONGLONG),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", LARGE_INTEGER),
        ("PerJobUserTimeLimit", LARGE_INTEGER),
        ("LimitFlags", DWORD),
        ("MinimumWorkingSetSize", SIZE_T),
        ("MaximumWorkingSetSize", SIZE_T),
        ("ActiveProcessLimit", DWORD),
        ("Affinity", ULONG_PTR),
        ("PriorityClass", DWORD),
        ("SchedulingClass", DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", SIZE_T),
        ("JobMemoryLimit", SIZE_T),
        ("PeakProcessMemoryUsed", SIZE_T),
        ("PeakJobMemoryUsed", SIZE_T),
    ]


class JOBOBJECT_BASIC_UI_RESTRICTIONS(ctypes.Structure):
    _fields_ = [("UIRestrictionsClass", DWORD)]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def job_limits(
    *,
    memory_bytes: int | None = None,
    cpu_seconds: float | None = None,
    max_processes: int | None = None,
    kill_on_close: bool = True,
) -> tuple[int, dict[str, int]]:
    """Return ``(LimitFlags, fields)`` for the extended limit information.

    ``fields`` maps structure member names (``ProcessMemoryLimit``,
    ``PerProcessUserTimeLimit`` in 100 ns units, ``ActiveProcessLimit``) to
    values.  ``JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`` is always set so
    a crashing worker never blocks on a dialog box.
    """
    flags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
    fields: dict[str, int] = {}
    if memory_bytes is not None:
        if memory_bytes <= 0:
            raise ValueError("memory_bytes must be positive")
        flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
        fields["ProcessMemoryLimit"] = int(memory_bytes)
    if cpu_seconds is not None:
        if cpu_seconds <= 0:
            raise ValueError("cpu_seconds must be positive")
        flags |= JOB_OBJECT_LIMIT_PROCESS_TIME
        fields["PerProcessUserTimeLimit"] = round(cpu_seconds * _HUNDRED_NS_PER_SECOND)
    if max_processes is not None:
        if max_processes <= 0:
            raise ValueError("max_processes must be positive")
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        fields["ActiveProcessLimit"] = int(max_processes)
    if kill_on_close:
        flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    return flags, fields


def extended_limit_information(
    *,
    memory_bytes: int | None = None,
    cpu_seconds: float | None = None,
    max_processes: int | None = None,
    kill_on_close: bool = True,
) -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION:
    """Fill a ``JOBOBJECT_EXTENDED_LIMIT_INFORMATION`` from :func:`job_limits`."""
    flags, fields = job_limits(
        memory_bytes=memory_bytes,
        cpu_seconds=cpu_seconds,
        max_processes=max_processes,
        kill_on_close=kill_on_close,
    )
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = flags
    if "PerProcessUserTimeLimit" in fields:
        info.BasicLimitInformation.PerProcessUserTimeLimit = fields["PerProcessUserTimeLimit"]
    if "ActiveProcessLimit" in fields:
        info.BasicLimitInformation.ActiveProcessLimit = fields["ActiveProcessLimit"]
    if "ProcessMemoryLimit" in fields:
        info.ProcessMemoryLimit = fields["ProcessMemoryLimit"]
    return info


# --------------------------------------------------------------------------- #
# kernel32 (lazy)
# --------------------------------------------------------------------------- #

_kernel32: Any = None
_kernel32_error: str | None = None


def _load_kernel32() -> Any:
    """Load kernel32 once and set prototypes; returns ``None`` off Windows."""
    global _kernel32, _kernel32_error
    if _kernel32 is not None or _kernel32_error is not None:
        return _kernel32
    if sys.platform != "win32":
        _kernel32_error = f"job objects need Windows (running on {sys.platform})"
        return None
    windll = getattr(ctypes, "WinDLL", None)
    if windll is None:
        _kernel32_error = "ctypes.WinDLL is unavailable"
        return None
    try:
        lib = windll("kernel32", use_last_error=True)
        lib.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        lib.CreateJobObjectW.restype = HANDLE
        lib.SetInformationJobObject.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD]
        lib.SetInformationJobObject.restype = BOOL
        lib.AssignProcessToJobObject.argtypes = [HANDLE, HANDLE]
        lib.AssignProcessToJobObject.restype = BOOL
        lib.TerminateJobObject.argtypes = [HANDLE, UINT]
        lib.TerminateJobObject.restype = BOOL
        lib.CloseHandle.argtypes = [HANDLE]
        lib.CloseHandle.restype = BOOL
    except (OSError, AttributeError) as exc:
        _kernel32_error = f"kernel32 failed to load: {exc}"
        return None
    _kernel32 = lib
    return lib


def _last_error(what: str) -> OSError:
    code = ctypes.get_last_error() if hasattr(ctypes, "get_last_error") else 0
    try:
        message = ctypes.FormatError(code)  # type: ignore[attr-defined]
    except Exception:
        message = f"error {code}"
    return OSError(code, f"{what} failed: {message}")


class JobObject:
    """A Windows job object handle with the limits this package uses."""

    def __init__(self, handle: int, *, flags: int = 0, fields: dict[str, int] | None = None) -> None:
        self._handle: int | None = handle
        self.flags = flags
        self.fields = dict(fields or {})

    @property
    def handle(self) -> int | None:
        return self._handle

    @staticmethod
    def available() -> bool:
        """True only on win32 when kernel32 loads."""
        return sys.platform == "win32" and _load_kernel32() is not None

    @staticmethod
    def unavailable_reason() -> str:
        if JobObject.available():
            return ""
        _load_kernel32()
        return _kernel32_error or "job objects unavailable"

    @classmethod
    def create(
        cls,
        *,
        memory_bytes: int | None = None,
        cpu_seconds: float | None = None,
        max_processes: int | None = None,
        kill_on_close: bool = True,
        ui_restrictions: bool = True,
    ) -> JobObject:
        kernel32 = _load_kernel32()
        if kernel32 is None:
            raise OSError(cls.unavailable_reason())
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise _last_error("CreateJobObjectW")
        job = cls(int(handle))
        try:
            info = extended_limit_information(
                memory_bytes=memory_bytes,
                cpu_seconds=cpu_seconds,
                max_processes=max_processes,
                kill_on_close=kill_on_close,
            )
            job.flags, job.fields = job_limits(
                memory_bytes=memory_bytes,
                cpu_seconds=cpu_seconds,
                max_processes=max_processes,
                kill_on_close=kill_on_close,
            )
            ok = kernel32.SetInformationJobObject(
                job._handle, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
            )
            if not ok:
                raise _last_error("SetInformationJobObject(JobObjectExtendedLimitInformation)")
            if ui_restrictions:
                ui = JOBOBJECT_BASIC_UI_RESTRICTIONS(JOB_OBJECT_UILIMIT_ALL)
                ok = kernel32.SetInformationJobObject(
                    job._handle, JobObjectBasicUIRestrictions, ctypes.byref(ui), ctypes.sizeof(ui)
                )
                if not ok:
                    raise _last_error("SetInformationJobObject(JobObjectBasicUIRestrictions)")
        except BaseException:
            job.close()
            raise
        return job

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        """Put ``process`` (and every process it creates) into the job."""
        kernel32 = _load_kernel32()
        if kernel32 is None or self._handle is None:
            raise OSError("job object is closed or unavailable")
        process_handle = getattr(process, "_handle", None)
        if process_handle is None:
            raise OSError("Popen object has no _handle (not a Windows process)")
        if not kernel32.AssignProcessToJobObject(self._handle, int(process_handle)):
            raise _last_error("AssignProcessToJobObject")

    def terminate(self, exit_code: int = 1) -> None:
        kernel32 = _load_kernel32()
        if kernel32 is None or self._handle is None:
            return
        if not kernel32.TerminateJobObject(self._handle, int(exit_code)):
            raise _last_error("TerminateJobObject")

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        kernel32 = _load_kernel32()
        if kernel32 is not None:
            kernel32.CloseHandle(handle)

    def __del__(self) -> None:  # pragma: no cover - best effort
        try:
            self.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Backend
# --------------------------------------------------------------------------- #

_STATIC_UNSUPPORTED: dict[str, str] = {
    FILESYSTEM_ALLOWLIST: "requires AppContainer/ACL confinement; not implemented",
    NO_AMBIENT_NETWORK: "requires AppContainer network capability model; not implemented",
    NO_NEW_PRIVILEGES: "no Windows equivalent of PR_SET_NO_NEW_PRIVS; not implemented",
    REDUCED_KERNEL_SURFACE: "no seccomp equivalent on Windows; not implemented",
}

_JOB_MECHANISMS: dict[str, str] = {
    MEMORY_CAPPED: "job object ProcessMemoryLimit",
    CPU_TIME_CAPPED: "job object PerProcessUserTimeLimit",
    PROCESS_COUNT_CAPPED: "job object ActiveProcessLimit",
    KILLED_WITH_HOST: "job object KILL_ON_JOB_CLOSE",
}


class WindowsBackend:
    """Job-object resource caps and host-death kill; no filesystem or network confinement."""

    name = BACKEND_NAME

    def __init__(self, *, platform: str = "win32") -> None:
        self._platform = platform
        self._capabilities: BackendCapabilities | None = None

    def capabilities(self) -> BackendCapabilities:
        if self._capabilities is not None:
            return self._capabilities
        supported: dict[str, str] = {
            OWN_ADDRESS_SPACE: "separate worker process",
            WALL_TIME_CAPPED: "host deadline kills the worker",
            CLEAN_ENVIRONMENT: "explicit environment + python -I",
            PRIVATE_TMP: "TEMP/TMP point to a private session directory",
        }
        unsupported = dict(_STATIC_UNSUPPORTED)
        notes: list[str] = []
        if JobObject.available():
            supported.update(_JOB_MECHANISMS)
        else:
            reason = f"Windows job objects unavailable: {JobObject.unavailable_reason()}"
            for name in _JOB_MECHANISMS:
                unsupported[name] = reason
            notes.append(reason)
        self._capabilities = BackendCapabilities(
            name=self.name,
            platform=self._platform,
            supported=supported,
            unsupported=unsupported,
            notes=tuple(notes),
        )
        return self._capabilities

    def plan(self, spec: IsolationSpec, *, python: str, worker_path: str, session_dir: str) -> LaunchPlan:
        capabilities = self.capabilities()
        refuse_unmet(spec, capabilities)
        paths = session_paths(session_dir)
        files = spec.files
        work_dir = files.workdir if files is not None and files.workdir else paths["work"]
        private_tmp = files is not None and files.private_tmp
        if spec.env.mode == "clean":
            env = clean_env(spec, tmp_dir=paths["tmp"], work_dir=work_dir, platform="win32")
        else:
            env = inherited_env(spec, tmp_dir=paths["tmp"] if private_tmp else None)

        policy = base_policy(spec, work_dir=work_dir)
        policy["rlimits"] = {}
        policy["landlock"] = None
        policy["unshare_net"] = None
        policy["no_new_privs"] = None
        policy["seccomp"] = None

        guarantees = universal_guarantees(spec)
        limits = spec.limits
        if limits.memory is not None:
            guarantees[MEMORY_CAPPED] = capabilities.supported[MEMORY_CAPPED]
        if limits.cpu_seconds is not None:
            guarantees[CPU_TIME_CAPPED] = capabilities.supported[CPU_TIME_CAPPED]
        if limits.max_processes is not None:
            guarantees[PROCESS_COUNT_CAPPED] = capabilities.supported[PROCESS_COUNT_CAPPED]
        if spec.env.mode == "clean":
            guarantees[CLEAN_ENVIRONMENT] = capabilities.supported[CLEAN_ENVIRONMENT]
        if private_tmp:
            guarantees[PRIVATE_TMP] = capabilities.supported[PRIVATE_TMP]
        guarantees[KILLED_WITH_HOST] = capabilities.supported[KILLED_WITH_HOST]

        notes = ["ActiveProcessLimit counts every process in the job, including the worker itself"]
        report = IsolationReport(
            backend=self.name,
            platform=self._platform,
            requested=spec.guarantees(),
            guarantees=guarantees,
            notes=tuple(notes),
        )
        return LaunchPlan(
            argv=python_argv(python, worker_path, spec),
            env=env,
            cwd=work_dir,
            policy=policy,
            report=report,
            popen_kwargs={"creationflags": CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW},
            required_applied=(),
            state={
                "limits": {
                    "memory_bytes": limits.memory_bytes,
                    "cpu_seconds": limits.cpu_seconds,
                    "max_processes": limits.max_processes,
                }
            },
        )

    def attach(self, process: subprocess.Popen[bytes], plan: LaunchPlan) -> None:
        """Create the job, apply the limits, and assign the worker before the policy is sent."""
        limits = plan.state.get("limits") or {}
        job = JobObject.create(
            memory_bytes=limits.get("memory_bytes"),
            cpu_seconds=limits.get("cpu_seconds"),
            max_processes=limits.get("max_processes"),
            kill_on_close=True,
            ui_restrictions=True,
        )
        try:
            job.assign(process)
        except BaseException:
            job.close()
            raise
        plan.state["job"] = job

    def kill(self, process: subprocess.Popen[bytes], plan: LaunchPlan) -> None:
        job = plan.state.get("job")
        if job is not None:
            try:
                job.terminate(1)
            except OSError:
                pass
        try:
            process.kill()
        except (ProcessLookupError, OSError):
            pass
        if job is not None:
            try:
                job.close()
            except OSError:
                pass


__all__ = [
    "BACKEND_NAME",
    "CREATE_BREAKAWAY_FROM_JOB",
    "CREATE_NEW_PROCESS_GROUP",
    "CREATE_NO_WINDOW",
    "IO_COUNTERS",
    "JOBOBJECT_BASIC_LIMIT_INFORMATION",
    "JOBOBJECT_BASIC_UI_RESTRICTIONS",
    "JOBOBJECT_EXTENDED_LIMIT_INFORMATION",
    "JOB_OBJECT_LIMIT_ACTIVE_PROCESS",
    "JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION",
    "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
    "JOB_OBJECT_LIMIT_PROCESS_MEMORY",
    "JOB_OBJECT_LIMIT_PROCESS_TIME",
    "JOB_OBJECT_UILIMIT_ALL",
    "JobObject",
    "WindowsBackend",
    "extended_limit_information",
    "job_limits",
]
