"""Backend contract shared by the operating-system confinement backends.

A backend turns an :class:`IsolationSpec` into a :class:`LaunchPlan`: the
argv/env/cwd used to spawn the worker, the JSON *policy* the worker applies to
itself before serving requests, and the :class:`IsolationReport` describing
which guarantee is provided by which mechanism.  ``plan()`` must raise
:class:`IsolationUnsupportedError` for any requested guarantee it cannot
provide.  It never downgrades silently.

Backends are pure planners plus two small process hooks (``attach`` after
spawn, ``kill`` for the whole process tree).  The host session in
``dspy_interpreters.local`` owns the process and the protocol.
"""

from __future__ import annotations

import os
import subprocess
import sys
import sysconfig
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from dspy_interpreters.isolation.spec import (
    GUARANTEES,
    OWN_ADDRESS_SPACE,
    WALL_TIME_CAPPED,
    IsolationReport,
    IsolationSpec,
    IsolationUnsupportedError,
)

POLICY_VERSION = 1


@dataclass
class LaunchPlan:
    """Everything the host needs to spawn and supervise one worker."""

    argv: list[str]
    env: dict[str, str]
    cwd: str | None
    policy: dict[str, Any]
    report: IsolationReport
    popen_kwargs: dict[str, Any] = field(default_factory=dict)
    # Policy items the worker MUST report as applied in its ready message.
    # Matching is by exact name or by ``name + ":"`` prefix (``"landlock"`` matches ``"landlock:abi4"``).
    required_applied: tuple[str, ...] = ()
    # Backend runtime handles (for example a Windows job object); owned by the backend.
    state: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BackendCapabilities:
    """Probe result: which guarantees a backend can provide on this machine."""

    name: str
    platform: str
    supported: Mapping[str, str]  # guarantee -> mechanism summary
    unsupported: Mapping[str, str]  # guarantee -> reason
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "platform": self.platform,
            "supported": dict(sorted(self.supported.items())),
            "unsupported": dict(sorted(self.unsupported.items())),
            "notes": list(self.notes),
        }


class Backend(Protocol):
    name: str

    def capabilities(self) -> BackendCapabilities: ...

    def plan(self, spec: IsolationSpec, *, python: str, worker_path: str, session_dir: str) -> LaunchPlan:
        """Build a launch plan or raise :class:`IsolationUnsupportedError`."""
        ...

    def attach(self, process: subprocess.Popen[bytes], plan: LaunchPlan) -> None:
        """Post-spawn hook (for example assign a Windows job object).  May raise."""
        ...

    def kill(self, process: subprocess.Popen[bytes], plan: LaunchPlan) -> None:
        """Kill the worker and every process it created."""
        ...


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def session_paths(session_dir: str) -> dict[str, str]:
    """Canonical sub-directories of a per-interpreter session directory."""
    return {
        "bootstrap": os.path.join(session_dir, "bootstrap"),
        "work": os.path.join(session_dir, "work"),
        "tmp": os.path.join(session_dir, "tmp"),
    }


def runtime_read_paths(python: str) -> list[str]:
    """Paths the Python runtime needs to read: executable, prefixes, stdlib, site-packages."""
    candidates: list[str] = [
        python,
        os.path.realpath(python),
        os.path.dirname(os.path.realpath(python)),
        sys.prefix,
        sys.base_prefix,
        sys.exec_prefix,
        sys.base_exec_prefix,
    ]
    for key in ("stdlib", "platstdlib", "purelib", "platlib", "include", "platinclude", "data"):
        try:
            value = sysconfig.get_path(key)
        except Exception:
            value = None
        if value:
            candidates.append(value)
    try:
        import site

        candidates.extend(site.getsitepackages())
    except Exception:
        pass
    candidates.extend(path for path in sys.path if path)
    return dedupe_paths(candidates)


_LINUX_SYSTEM_READ = (
    "/usr",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/bin",
    "/sbin",
    "/opt",
    "/nix/store",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/alternatives",
    "/etc/localtime",
    "/etc/timezone",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/pki",
    "/etc/python3",
    "/etc/os-release",
    "/usr/lib/os-release",
)

_DARWIN_SYSTEM_READ = (
    "/usr/lib",
    "/usr/share",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local",
    "/opt/homebrew",
    "/opt/local",
    "/bin",
    "/sbin",
    "/System",
    "/Library/Frameworks",
    "/Library/Apple",
    "/Library/Preferences/Logging",
    "/private/etc",
    "/etc",
    # Narrow /private/var entries only: /var/folders holds $TMPDIR, i.e. the host's temp files and
    # every other session's work/ and tmp/ directories.
    "/private/var/db/dyld",
    "/private/var/db/timezone",
    "/private/var/select",
    "/private/var/run",
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/dtracehelper",
    "/dev/autofs_nowait",
)


def system_read_paths(platform: str = sys.platform) -> tuple[str, ...]:
    """Operating-system directories a Python process needs to read."""
    if platform.startswith("linux"):
        return _LINUX_SYSTEM_READ
    if platform == "darwin":
        return _DARWIN_SYSTEM_READ
    return ()


def dedupe_paths(paths: Iterable[str]) -> list[str]:
    """Absolute, normalized, existing paths with descendants of listed dirs removed."""
    seen: list[str] = []
    for path in paths:
        if not path:
            continue
        normalized = os.path.normpath(os.path.abspath(path))
        if not os.path.exists(normalized) and not os.path.islink(normalized):
            continue
        if normalized not in seen:
            seen.append(normalized)
    seen.sort(key=lambda p: (len(p.split(os.sep)), p))
    kept: list[str] = []
    for path in seen:
        if any(path == parent or path.startswith(parent.rstrip(os.sep) + os.sep) for parent in kept):
            continue
        kept.append(path)
    return kept


def clean_env(spec: IsolationSpec, *, tmp_dir: str, work_dir: str, platform: str = sys.platform) -> dict[str, str]:
    """Environment for a clean worker: minimal defaults plus passthrough and explicit variables."""
    env: dict[str, str] = {}
    if platform == "win32":
        for name in ("SYSTEMROOT", "SYSTEMDRIVE", "PATH", "PATHEXT", "COMSPEC", "TEMP", "TMP", "WINDIR"):
            if name in os.environ:
                env[name] = os.environ[name]
        env["TEMP"] = tmp_dir
        env["TMP"] = tmp_dir
    else:
        env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
        env["TMPDIR"] = tmp_dir
        env["HOME"] = work_dir
        env["LANG"] = "C.UTF-8"
        env["LC_ALL"] = "C.UTF-8"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for name in spec.env.passthrough:
        if name in os.environ:
            env[name] = os.environ[name]
    env.update(spec.env.variables)
    return env


def inherited_env(spec: IsolationSpec, *, tmp_dir: str | None = None) -> dict[str, str]:
    env = dict(os.environ)
    if tmp_dir is not None and spec.files is not None and spec.files.private_tmp:
        env["TMPDIR"] = tmp_dir
        env["TEMP"] = tmp_dir
        env["TMP"] = tmp_dir
    env.update(spec.env.variables)
    return env


def python_argv(python: str, worker_path: str, spec: IsolationSpec) -> list[str]:
    """Interpreter command: isolated mode (-I) for clean environments, plain otherwise."""
    argv = [python]
    if spec.env.mode == "clean":
        argv.append("-I")
    argv.extend(["-u", worker_path])
    return argv


def base_policy(spec: IsolationSpec, *, work_dir: str) -> dict[str, Any]:
    """Policy fields common to all backends; backends add their own keys."""
    limits = spec.limits
    rlimits: dict[str, Any] = {"core": 0}
    if limits.cpu_seconds is not None:
        rlimits["cpu"] = int(limits.cpu_seconds) + 1
    return {
        "version": POLICY_VERSION,
        "die_with_parent": True,
        "pgroup_reaper": False,
        "chdir": work_dir,
        "rlimits": rlimits,
        "landlock": None,
        "unshare_net": None,
        "no_new_privs": None,
        "seccomp": None,
    }


def refuse_unmet(spec: IsolationSpec, capabilities: BackendCapabilities) -> None:
    """Raise if the specification wants a guarantee this backend cannot provide."""
    unmet = {
        name: capabilities.unsupported.get(name, "not provided by this backend")
        for name in sorted(spec.guarantees())
        if name not in capabilities.supported
    }
    if unmet:
        raise IsolationUnsupportedError(unmet, backend=capabilities.name)


def universal_guarantees(spec: IsolationSpec) -> dict[str, str]:
    """Guarantees every subprocess backend provides through the host session itself."""
    provided = {OWN_ADDRESS_SPACE: "separate worker process"}
    if spec.limits.wall_time_seconds is not None:
        provided[WALL_TIME_CAPPED] = "host deadline kills the worker"
    return provided


def describe_unknown(names: Iterable[str]) -> dict[str, str]:
    return {name: GUARANTEES.get(name, "unknown guarantee") for name in names}


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #


def get_backend(platform: str = sys.platform) -> Backend:
    """The native backend for ``platform`` (linux, darwin, win32) or the plain one."""
    if platform.startswith("linux"):
        from dspy_interpreters.isolation._linux import LinuxBackend

        return LinuxBackend()
    if platform == "darwin":
        from dspy_interpreters.isolation._darwin import DarwinBackend

        return DarwinBackend()
    if platform == "win32":
        from dspy_interpreters.isolation._windows import WindowsBackend

        return WindowsBackend()
    from dspy_interpreters.isolation._plain import PlainBackend

    return PlainBackend(platform=platform)


def select_backend(spec: IsolationSpec, platform: str = sys.platform) -> Backend:
    """Return the backend for this platform after checking it can meet ``spec``.

    Raises :class:`IsolationUnsupportedError` (a ``CodeInterpreterError``) with
    one reason per unmet guarantee.  Plain, unconfined specifications use the
    portable :class:`PlainBackend`.
    """
    if not spec.is_confined:
        from dspy_interpreters.isolation._plain import PlainBackend

        backend: Backend = PlainBackend(platform=platform)
    else:
        backend = get_backend(platform)
    refuse_unmet(spec, backend.capabilities())
    return backend


def probe(platform: str = sys.platform) -> BackendCapabilities:
    """Report what the native backend can enforce on this machine."""
    return get_backend(platform).capabilities()


__all__ = [
    "POLICY_VERSION",
    "Backend",
    "BackendCapabilities",
    "LaunchPlan",
    "base_policy",
    "clean_env",
    "dedupe_paths",
    "describe_unknown",
    "get_backend",
    "inherited_env",
    "probe",
    "python_argv",
    "refuse_unmet",
    "runtime_read_paths",
    "select_backend",
    "session_paths",
    "system_read_paths",
    "universal_guarantees",
]
