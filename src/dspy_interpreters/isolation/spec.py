"""Guarantee-based isolation specification for on-machine interpreters.

The vocabulary is portable *guarantees*, not operating-system mechanisms.
A backend either provides a requested guarantee or refuses loudly at
``start()``; it never silently substitutes a weaker mechanism.  A backend may
exceed the request (floor semantics) and reports every mechanism it applied in
an :class:`IsolationReport`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from dspy import CodeInterpreterError

# --------------------------------------------------------------------------- #
# Guarantee vocabulary
# --------------------------------------------------------------------------- #

OWN_ADDRESS_SPACE = "own_address_space"
FILESYSTEM_ALLOWLIST = "filesystem_allowlist"
NO_AMBIENT_NETWORK = "no_ambient_network"
MEMORY_CAPPED = "memory_capped"
CPU_TIME_CAPPED = "cpu_time_capped"
PROCESS_COUNT_CAPPED = "process_count_capped"
WALL_TIME_CAPPED = "wall_time_capped"
CLEAN_ENVIRONMENT = "clean_environment"
PRIVATE_TMP = "private_tmp"
KILLED_WITH_HOST = "killed_with_host"
NO_NEW_PRIVILEGES = "no_new_privileges"
REDUCED_KERNEL_SURFACE = "reduced_kernel_surface"

GUARANTEES: Mapping[str, str] = {
    OWN_ADDRESS_SPACE: "Generated code runs in a separate operating-system process, not in the DSPy process.",
    FILESYSTEM_ALLOWLIST: "Only listed paths are readable or writable; everything else is denied.",
    NO_AMBIENT_NETWORK: "The worker has no network stack access; host tools are the only external channel.",
    MEMORY_CAPPED: "Worker memory is capped; exceeding the cap fails the allocation or kills the worker.",
    CPU_TIME_CAPPED: "Worker CPU time is capped; exceeding the cap kills the worker.",
    PROCESS_COUNT_CAPPED: "The number of processes the worker can create is capped.",
    WALL_TIME_CAPPED: "Each execute() call has a wall-clock deadline; exceeding it kills the worker.",
    CLEAN_ENVIRONMENT: "Host environment variables are not inherited except an explicit passthrough list.",
    PRIVATE_TMP: "The worker sees a private temporary directory instead of the shared host one.",
    KILLED_WITH_HOST: "The worker is killed when the host process dies.",
    NO_NEW_PRIVILEGES: "The worker cannot gain privileges through setuid/setgid or file capabilities.",
    REDUCED_KERNEL_SURFACE: "A syscall denylist blocks ptrace, mounts, modules, bpf, keyrings, and namespaces.",
}

_MEMORY_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)(?:i?b)?\s*$", re.IGNORECASE)
_MEMORY_UNITS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_memory(value: int | str) -> int:
    """Return a byte count for ``1024``, ``"512M"``, ``"2GiB"``, ``"1.5g"``."""
    if isinstance(value, bool):
        raise IsolationSpecError("memory must be a byte count or a size string")
    if isinstance(value, int):
        if value <= 0:
            raise IsolationSpecError("memory must be positive")
        return value
    if not isinstance(value, str):
        raise IsolationSpecError("memory must be a byte count or a size string")
    match = _MEMORY_RE.match(value)
    if match is None:
        raise IsolationSpecError(f"invalid memory size: {value!r}")
    number, unit = match.groups()
    result = int(float(number) * _MEMORY_UNITS[unit.lower()])
    if result <= 0:
        raise IsolationSpecError("memory must be positive")
    return result


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class IsolationError(CodeInterpreterError):
    """Base class for isolation configuration and enforcement failures."""


class IsolationSpecError(IsolationError, ValueError):
    """The specification itself is invalid."""


class IsolationUnsupportedError(IsolationError):
    """The current backend cannot provide one or more requested guarantees.

    ``unmet`` maps each guarantee name to a human-readable reason.
    """

    def __init__(self, unmet: Mapping[str, str], backend: str | None = None) -> None:
        self.unmet = dict(unmet)
        self.backend = backend
        where = f" on backend {backend!r}" if backend else ""
        details = "; ".join(f"{name}: {reason}" for name, reason in self.unmet.items())
        super().__init__(f"Requested isolation guarantees are not available{where}: {details}")


# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FilesystemPolicy:
    """Filesystem allowlist.

    ``read`` and ``write`` are absolute paths (files or directories).  With
    ``include_runtime`` the Python runtime (prefix, stdlib, site-packages) and
    the operating-system library directories are readable.  ``workdir`` is a
    writable directory used as the worker's current directory; ``None`` means a
    private per-session directory.
    """

    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()
    include_runtime: bool = True
    private_tmp: bool = True
    workdir: str | None = None


@dataclass(frozen=True)
class NetworkPolicy:
    """``"host"`` inherits the host network; ``"none"`` removes network access."""

    mode: Literal["host", "none"] = "host"


@dataclass(frozen=True)
class ResourceLimits:
    """Resource caps.  ``None`` means uncapped (no guarantee requested)."""

    memory: int | str | None = None
    cpu_seconds: float | None = None
    max_processes: int | None = None
    wall_time_seconds: float | None = None

    @property
    def memory_bytes(self) -> int | None:
        return None if self.memory is None else parse_memory(self.memory)


@dataclass(frozen=True)
class EnvPolicy:
    """``"inherit"`` copies the host environment; ``"clean"`` starts empty.

    With ``"clean"``, ``passthrough`` names are copied from the host and
    ``variables`` are set explicitly.  Backends always set the variables the
    worker needs to start (``PATH``, ``TMPDIR``, locale).
    """

    mode: Literal["inherit", "clean"] = "inherit"
    passthrough: tuple[str, ...] = ()
    variables: Mapping[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Specification
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class IsolationSpec:
    """What the caller requires from an on-machine worker.

    Every non-default field is a *required* guarantee.  ``require`` adds named
    guarantees that have no parameters (for example ``no_new_privileges``).
    ``backend_options`` tunes mechanisms without changing guarantees, for
    example ``{"linux.launcher": "bwrap" | "native" | "auto"}`` or
    ``{"darwin.profile_extra": "(allow ...)"}``.
    """

    files: FilesystemPolicy | None = None
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    env: EnvPolicy = field(default_factory=EnvPolicy)
    require: frozenset[str] = frozenset()
    backend_options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "require", frozenset(self.require))
        self.validate()

    # -- validation -------------------------------------------------------- #

    def validate(self) -> None:
        unknown = sorted(name for name in self.require if name not in GUARANTEES)
        if unknown:
            raise IsolationSpecError(f"unknown guarantees in require: {unknown}")
        if self.network.mode not in ("host", "none"):
            raise IsolationSpecError(f"network mode must be 'host' or 'none', not {self.network.mode!r}")
        if self.env.mode not in ("inherit", "clean"):
            raise IsolationSpecError(f"env mode must be 'inherit' or 'clean', not {self.env.mode!r}")
        limits = self.limits
        limits.memory_bytes  # noqa: B018 - validates the size string
        for name in ("cpu_seconds", "wall_time_seconds"):
            value = getattr(limits, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0):
                raise IsolationSpecError(f"{name} must be a positive number")
        if limits.max_processes is not None and (
            isinstance(limits.max_processes, bool)
            or not isinstance(limits.max_processes, int)
            or limits.max_processes <= 0
        ):
            raise IsolationSpecError("max_processes must be a positive integer")
        if self.files is not None:
            for group in ("read", "write"):
                paths = getattr(self.files, group)
                if isinstance(paths, str) or not all(isinstance(path, str) and path for path in paths):
                    raise IsolationSpecError(f"files.{group} must be a tuple of non-empty path strings")
            if self.files.workdir is not None and not isinstance(self.files.workdir, str):
                raise IsolationSpecError("files.workdir must be a path string or None")
        if not isinstance(self.env.passthrough, tuple) or not all(isinstance(n, str) for n in self.env.passthrough):
            raise IsolationSpecError("env.passthrough must be a tuple of names")
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in self.env.variables.items()):
            raise IsolationSpecError("env.variables must map names to string values")

    # -- derived guarantees ------------------------------------------------- #

    def guarantees(self) -> frozenset[str]:
        """Guarantees this specification requires from the backend."""
        wanted = {OWN_ADDRESS_SPACE, KILLED_WITH_HOST}
        if self.files is not None:
            wanted.add(FILESYSTEM_ALLOWLIST)
            if self.files.private_tmp:
                wanted.add(PRIVATE_TMP)
        if self.network.mode == "none":
            wanted.add(NO_AMBIENT_NETWORK)
        if self.limits.memory is not None:
            wanted.add(MEMORY_CAPPED)
        if self.limits.cpu_seconds is not None:
            wanted.add(CPU_TIME_CAPPED)
        if self.limits.max_processes is not None:
            wanted.add(PROCESS_COUNT_CAPPED)
        if self.limits.wall_time_seconds is not None:
            wanted.add(WALL_TIME_CAPPED)
        if self.env.mode == "clean":
            wanted.add(CLEAN_ENVIRONMENT)
        wanted.update(self.require)
        return frozenset(wanted)

    @property
    def is_confined(self) -> bool:
        """True when anything beyond a plain worker process is requested."""
        return bool(self.guarantees() - {OWN_ADDRESS_SPACE, KILLED_WITH_HOST, WALL_TIME_CAPPED})

    # -- presets ----------------------------------------------------------- #

    @classmethod
    def trusted(cls, *, wall_time_seconds: float | None = None) -> IsolationSpec:
        """A plain worker process: own address space, host filesystem, host network."""
        return cls(limits=ResourceLimits(wall_time_seconds=wall_time_seconds))

    @classmethod
    def confined(
        cls,
        *,
        read: tuple[str, ...] = (),
        write: tuple[str, ...] = (),
        workdir: str | None = None,
        network: Literal["host", "none"] = "none",
        memory: int | str | None = "1G",
        cpu_seconds: float | None = 120.0,
        max_processes: int | None = 32,
        wall_time_seconds: float | None = 120.0,
        env_passthrough: tuple[str, ...] = (),
        require: frozenset[str] | set[str] = frozenset(),
        backend_options: Mapping[str, Any] | None = None,
    ) -> IsolationSpec:
        """Filesystem allowlist, clean environment, no network, and resource caps."""
        return cls(
            files=FilesystemPolicy(read=tuple(read), write=tuple(write), workdir=workdir),
            network=NetworkPolicy(mode=network),
            limits=ResourceLimits(
                memory=memory,
                cpu_seconds=cpu_seconds,
                max_processes=max_processes,
                wall_time_seconds=wall_time_seconds,
            ),
            env=EnvPolicy(mode="clean", passthrough=tuple(env_passthrough)),
            require=frozenset(require),
            backend_options=dict(backend_options or {}),
        )

    def describe(self) -> str:
        """Stable one-line description used in execution instructions."""
        parts = []
        parts.append("filesystem limited to an allowlist" if self.files is not None else "host filesystem")
        parts.append("no network access" if self.network.mode == "none" else "host network")
        caps = []
        if self.limits.memory is not None:
            caps.append(f"memory {self.limits.memory}")
        if self.limits.cpu_seconds is not None:
            caps.append(f"CPU {self.limits.cpu_seconds:g}s")
        if self.limits.max_processes is not None:
            caps.append(f"processes {self.limits.max_processes}")
        if self.limits.wall_time_seconds is not None:
            caps.append(f"wall time {self.limits.wall_time_seconds:g}s per execution")
        parts.append("limits: " + ", ".join(caps) if caps else "no resource limits")
        parts.append("clean environment" if self.env.mode == "clean" else "inherited environment")
        return "; ".join(parts)


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class IsolationReport:
    """What a running worker actually got.

    ``guarantees`` maps every provided guarantee to the mechanism used, for
    example ``{"no_ambient_network": "bwrap --unshare-net"}``.  ``requested``
    lists what the specification asked for; every requested guarantee is
    present in ``guarantees`` (otherwise ``start()`` refused).  Extra entries
    are guarantees the backend applied beyond the request.
    """

    backend: str
    platform: str
    requested: frozenset[str]
    guarantees: Mapping[str, str]
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "requested", frozenset(self.requested))
        object.__setattr__(self, "guarantees", dict(self.guarantees))
        object.__setattr__(self, "notes", tuple(self.notes))

    @property
    def extras(self) -> dict[str, str]:
        return {name: how for name, how in self.guarantees.items() if name not in self.requested}

    @property
    def missing(self) -> frozenset[str]:
        return frozenset(name for name in self.requested if name not in self.guarantees)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "platform": self.platform,
            "requested": sorted(self.requested),
            "guarantees": dict(sorted(self.guarantees.items())),
            "notes": list(self.notes),
        }


__all__ = [
    "CLEAN_ENVIRONMENT",
    "CPU_TIME_CAPPED",
    "FILESYSTEM_ALLOWLIST",
    "GUARANTEES",
    "KILLED_WITH_HOST",
    "MEMORY_CAPPED",
    "NO_AMBIENT_NETWORK",
    "NO_NEW_PRIVILEGES",
    "OWN_ADDRESS_SPACE",
    "PRIVATE_TMP",
    "PROCESS_COUNT_CAPPED",
    "REDUCED_KERNEL_SURFACE",
    "WALL_TIME_CAPPED",
    "EnvPolicy",
    "FilesystemPolicy",
    "IsolationError",
    "IsolationReport",
    "IsolationSpec",
    "IsolationSpecError",
    "IsolationUnsupportedError",
    "NetworkPolicy",
    "ResourceLimits",
    "parse_memory",
]
