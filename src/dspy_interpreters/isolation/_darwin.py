"""macOS backend: ``sandbox-exec`` with a generated SBPL profile plus POSIX rlimits.

The profile denies everything by default and allowlists the Python runtime,
the operating-system directories, and the paths named in the specification.
Apple documents ``sandbox-exec`` as deprecated and the SBPL syntax is not
public, so the profile is marked *experimental* in every report.

Guarantees provided: filesystem_allowlist and no_ambient_network (sandbox
profile), private_tmp, clean_environment, cpu_time_capped (``RLIMIT_CPU``),
process_count_capped (``RLIMIT_NPROC``, a per-user count), killed_with_host
(worker ppid watchdog), own_address_space and wall_time_capped (host).
``memory_capped`` is refused: macOS accepts ``RLIMIT_AS`` but does not enforce
it and there is no cgroup equivalent.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from collections.abc import Iterable, Sequence

from dspy_interpreters.isolation._backend import (
    BackendCapabilities,
    LaunchPlan,
    base_policy,
    clean_env,
    dedupe_paths,
    inherited_env,
    python_argv,
    refuse_unmet,
    runtime_read_paths,
    session_paths,
    system_read_paths,
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

BACKEND_NAME = "darwin-sandbox-exec"
DEFAULT_SANDBOX_EXEC = "/usr/bin/sandbox-exec"

MACH_SERVICES: tuple[str, ...] = (
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.logger",
    "com.apple.system.notification_center",
    "com.apple.SecurityServer",
    "com.apple.CoreServices.coreservicesd",
)
# Name resolution goes through the dnssd XPC service; only meaningful when the network is allowed.
NETWORK_MACH_SERVICES: tuple[str, ...] = ("com.apple.dnssd.service",)

_PROFILE_NOTE = (
    "sandbox-exec profile is experimental: Apple deprecates sandbox-exec and the SBPL syntax is undocumented; "
    "some Python packages may need extra rules via backend_options['darwin.profile_extra']"
)
_NPROC_NOTE = "RLIMIT_NPROC counts every process of the current user, not only the worker's descendants"
_REAPER_NOTE = (
    "the ppid watchdog ends the worker process itself; a helper forked by the worker then SIGKILLs the worker's "
    "process group, so guest processes survive only if they left the session (setsid)"
)

_UNSUPPORTED: dict[str, str] = {
    MEMORY_CAPPED: "macOS does not enforce RLIMIT_AS; no cgroup equivalent",
    NO_NEW_PRIVILEGES: "macOS has no PR_SET_NO_NEW_PRIVS equivalent; not implemented",
    REDUCED_KERNEL_SURFACE: "macOS has no seccomp equivalent; not implemented",
}


# --------------------------------------------------------------------------- #
# Profile builder (pure)
# --------------------------------------------------------------------------- #


def escape_path(path: str) -> str:
    """Escape a path for use inside an SBPL string literal."""
    return path.replace("\\", "\\\\").replace('"', '\\"')


def _path_filter(path: str) -> str:
    kind = "subpath" if os.path.isdir(path) else "literal"
    return f'({kind} "{escape_path(path)}")'


def _path_filters(paths: Iterable[str]) -> list[str]:
    """One filter per path (directories -> subpath, files -> literal); symlink targets are added too."""
    filters: list[str] = []
    for path in paths:
        if not path:
            continue
        for candidate in (path, os.path.realpath(path)):
            entry = _path_filter(candidate)
            if entry not in filters:
                filters.append(entry)
    return filters


def _rule(operation: str, filters: Sequence[str]) -> str:
    return f"(allow {operation} {' '.join(filters)})"


def build_profile(
    spec: IsolationSpec,
    *,
    read_paths: Sequence[str],
    write_paths: Sequence[str],
    network_allowed: bool,
    exec_paths: Sequence[str] | None = None,
) -> str:
    """Return the SBPL profile text for ``spec``.

    ``read_paths`` and ``write_paths`` are absolute host paths (directories use
    ``subpath``, files use ``literal``).  Write paths are also readable: SBPL
    ``file-write*`` does not include ``file-read*``, so the rule for them is
    ``(allow file-read* file-write* ...)``.  ``exec_paths`` defaults to
    ``read_paths``.  ``spec.backend_options["darwin.profile_extra"]`` is
    appended verbatim as the last lines.
    """
    lines = [
        "(version 1)",
        "(deny default)",
        "(allow file-read-metadata)",
        "(allow process-fork)",
    ]
    exec_filters = _path_filters(read_paths if exec_paths is None else exec_paths)
    if exec_filters:
        lines.append(_rule("process-exec", exec_filters))
    lines.append("(allow signal (target self))")
    lines.append("(allow sysctl-read)")
    services = [*MACH_SERVICES, *(NETWORK_MACH_SERVICES if network_allowed else ())]
    lines.append(_rule("mach-lookup", [f'(global-name "{name}")' for name in services]))
    read_filters = _path_filters(read_paths)
    if read_filters:
        lines.append(_rule("file-read*", read_filters))
    write_filters = _path_filters(write_paths)
    if write_filters:
        lines.append(_rule("file-read* file-write*", write_filters))
    lines.append('(allow file-read* file-write-data file-ioctl (literal "/dev/dtracehelper") (literal "/dev/null"))')
    lines.append('(allow file-write* (literal "/dev/null"))')
    lines.append("(allow ipc-posix-shm)")
    lines.append("(allow ipc-posix-sem)")
    lines.append("(allow network*)" if network_allowed else "(deny network*)")
    extra = spec.backend_options.get("darwin.profile_extra", "")
    if extra:
        lines.append(str(extra).strip())
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Backend
# --------------------------------------------------------------------------- #


def locate_sandbox_exec() -> str | None:
    """Path of ``sandbox-exec`` or ``None``.  Never runs a subprocess."""
    found = shutil.which("sandbox-exec")
    if found:
        return found
    if os.path.exists(DEFAULT_SANDBOX_EXEC):
        return DEFAULT_SANDBOX_EXEC
    return None


def _merge(first: Iterable[str], second: Iterable[str]) -> list[str]:
    merged: list[str] = []
    for path in [*first, *second]:
        normalized = os.path.normpath(os.path.abspath(path))
        if normalized not in merged:
            merged.append(normalized)
    return merged


class DarwinBackend:
    """``sandbox-exec`` profile + rlimits.  Pure planning works on every OS."""

    name = BACKEND_NAME

    def __init__(self, *, sandbox_exec: str | None = None, platform: str = "darwin") -> None:
        self._sandbox_exec_override = sandbox_exec
        self._platform = platform
        self._capabilities: BackendCapabilities | None = None
        self._sandbox_exec: str | None = None

    # -- probe ---------------------------------------------------------------- #

    def _probe_sandbox_exec(self) -> tuple[str | None, str | None]:
        """Return ``(path, failure_reason)``; only shells out on macOS."""
        path = self._sandbox_exec_override or locate_sandbox_exec()
        if path is None:
            return None, "sandbox-exec not found"
        if self._sandbox_exec_override is not None or sys.platform != "darwin":
            return path, None
        try:
            probe = subprocess.run(
                [path, "-p", "(version 1)(allow default)", "--", "/usr/bin/true"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return None, f"sandbox-exec failed to run: {exc}"
        if probe.returncode != 0:
            detail = probe.stderr.decode("utf-8", "replace").strip()
            return None, f"sandbox-exec probe failed (exit {probe.returncode}): {detail or 'no output'}"
        return path, None

    def capabilities(self) -> BackendCapabilities:
        if self._capabilities is not None:
            return self._capabilities
        path, failure = self._probe_sandbox_exec()
        self._sandbox_exec = path
        supported: dict[str, str] = {
            OWN_ADDRESS_SPACE: "separate worker process",
            WALL_TIME_CAPPED: "host deadline kills the worker",
            CLEAN_ENVIRONMENT: "explicit environment + python -I",
            CPU_TIME_CAPPED: "RLIMIT_CPU",
            PROCESS_COUNT_CAPPED: "RLIMIT_NPROC (per-user process count)",
            KILLED_WITH_HOST: "worker ppid watchdog",
        }
        unsupported = dict(_UNSUPPORTED)
        notes = [_PROFILE_NOTE, _NPROC_NOTE]
        if path is not None:
            supported[FILESYSTEM_ALLOWLIST] = "sandbox-exec SBPL profile (deny default, allowlisted paths)"
            supported[NO_AMBIENT_NETWORK] = "sandbox-exec (deny network*)"
            supported[PRIVATE_TMP] = "private TMPDIR under the session directory, allowlisted in the profile"
        else:
            reason = failure or "sandbox-exec not found"
            unsupported[FILESYSTEM_ALLOWLIST] = reason
            unsupported[NO_AMBIENT_NETWORK] = reason
            unsupported[PRIVATE_TMP] = reason
        self._capabilities = BackendCapabilities(
            name=self.name,
            platform=self._platform,
            supported=supported,
            unsupported=unsupported,
            notes=tuple(notes),
        )
        return self._capabilities

    # -- planning ------------------------------------------------------------ #

    def plan(self, spec: IsolationSpec, *, python: str, worker_path: str, session_dir: str) -> LaunchPlan:
        capabilities = self.capabilities()
        refuse_unmet(spec, capabilities)
        paths = session_paths(session_dir)
        files = spec.files
        work_dir = files.workdir if files is not None and files.workdir else paths["work"]
        private_tmp = files is not None and files.private_tmp
        tmp_dir = paths["tmp"] if private_tmp else None

        if spec.env.mode == "clean":
            env = clean_env(spec, tmp_dir=tmp_dir or paths["tmp"], work_dir=work_dir, platform="darwin")
            if tmp_dir is None:
                env["TMPDIR"] = os.environ.get("TMPDIR", "/tmp")
        else:
            env = inherited_env(spec, tmp_dir=tmp_dir)

        argv = python_argv(python, worker_path, spec)
        use_sandbox = files is not None or spec.network.mode == "none"
        guarantees = universal_guarantees(spec)
        notes: list[str] = []
        if use_sandbox:
            sandbox_exec = self._sandbox_exec or self._sandbox_exec_override or DEFAULT_SANDBOX_EXEC
            profile = build_profile(
                spec,
                read_paths=self._read_paths(spec, python=python, worker_path=worker_path, paths=paths),
                write_paths=self._write_paths(spec, work_dir=work_dir, tmp_dir=tmp_dir, env=env),
                network_allowed=spec.network.mode != "none",
                # Without a files policy the sandbox only removes the network: exec follows the read paths ("/").
                exec_paths=None
                if files is None
                else dedupe_paths([*runtime_read_paths(python), *system_read_paths("darwin")]),
            )
            argv = [sandbox_exec, "-p", profile, "--", *argv]
            notes.append(_PROFILE_NOTE)
            if files is not None:
                guarantees[FILESYSTEM_ALLOWLIST] = capabilities.supported[FILESYSTEM_ALLOWLIST]
                if private_tmp:
                    guarantees[PRIVATE_TMP] = capabilities.supported[PRIVATE_TMP]
            if spec.network.mode == "none":
                guarantees[NO_AMBIENT_NETWORK] = capabilities.supported[NO_AMBIENT_NETWORK]

        policy = base_policy(spec, work_dir=work_dir)
        policy["pgroup_reaper"] = True  # the worker owns its session (start_new_session): a helper may killpg it
        required: list[str] = ["ppid_watchdog"]
        notes.append(_REAPER_NOTE)
        if spec.limits.cpu_seconds is not None:
            guarantees[CPU_TIME_CAPPED] = capabilities.supported[CPU_TIME_CAPPED]
            required.append("rlimit:cpu")
        if spec.limits.max_processes is not None:
            policy["rlimits"]["nproc"] = int(spec.limits.max_processes)
            guarantees[PROCESS_COUNT_CAPPED] = capabilities.supported[PROCESS_COUNT_CAPPED]
            required.append("rlimit:nproc")
            notes.append(_NPROC_NOTE)
        if spec.env.mode == "clean":
            guarantees[CLEAN_ENVIRONMENT] = capabilities.supported[CLEAN_ENVIRONMENT]
        guarantees[KILLED_WITH_HOST] = capabilities.supported[KILLED_WITH_HOST]

        report = IsolationReport(
            backend=self.name,
            platform=self._platform,
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
            popen_kwargs={"start_new_session": True},
            required_applied=tuple(required),
        )

    @staticmethod
    def _read_paths(spec: IsolationSpec, *, python: str, worker_path: str, paths: dict[str, str]) -> list[str]:
        files = spec.files
        if files is None:
            return ["/"]
        candidates: list[str] = [worker_path, os.path.dirname(worker_path)]
        if files.include_runtime:
            candidates.extend(runtime_read_paths(python))
            candidates.extend(system_read_paths("darwin"))
        candidates.extend(files.read)
        # The bootstrap directory is created by the host; keep it even if it does not exist yet.
        return _merge([paths["bootstrap"]], dedupe_paths(candidates))

    @staticmethod
    def _write_paths(spec: IsolationSpec, *, work_dir: str, tmp_dir: str | None, env: dict[str, str]) -> list[str]:
        files = spec.files
        if files is None:
            return ["/"]
        always: list[str] = [work_dir]
        if tmp_dir is not None:
            always.append(tmp_dir)
        else:
            always.append(env.get("TMPDIR") or "/tmp")
        # Session directories are created by the host; keep them even if they do not exist yet.
        return _merge(always, dedupe_paths(files.write))

    # -- process hooks -------------------------------------------------------- #

    def attach(self, process: subprocess.Popen[bytes], plan: LaunchPlan) -> None:
        return None

    def kill(self, process: subprocess.Popen[bytes], plan: LaunchPlan) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError, AttributeError):
            pass
        try:
            process.kill()
        except (ProcessLookupError, OSError):
            pass


__all__ = [
    "BACKEND_NAME",
    "MACH_SERVICES",
    "NETWORK_MACH_SERVICES",
    "DarwinBackend",
    "build_profile",
    "escape_path",
    "locate_sandbox_exec",
]
