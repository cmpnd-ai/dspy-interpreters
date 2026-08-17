"""Linux confinement backend: bubblewrap or native Landlock/namespaces, plus cgroups.

Two launchers are available and selected through
``spec.backend_options["linux.launcher"]`` (``"auto"`` by default):

``bwrap``
    The worker starts inside a `bubblewrap <https://github.com/containers/bubblewrap>`_
    sandbox: an empty root with read-only bind mounts for the Python runtime,
    the operating-system libraries, and the requested read paths; writable bind
    mounts for the work directory, the session tmp (``TMPDIR``), and the
    requested write paths; a private tmpfs ``/tmp``; fresh ``/proc`` and ``/dev``; new user, pid, ipc,
    uts (and, without network, net) namespaces; ``--die-with-parent``.
``native``
    No wrapper.  The worker confines itself with Landlock (filesystem
    allowlist) and ``unshare(CLONE_NEWUSER | CLONE_NEWNET)`` (no network),
    both *required*, plus the seccomp filter (also required) that denies
    ``socket(AF_UNIX)``: neither Landlock nor the network namespace stops
    ``connect()`` to a filesystem-path Unix socket of the host.

Both launchers additionally send RLIMIT_CPU/RLIMIT_CORE, ``no_new_privs`` and
the seccomp denylist (required only when named in ``spec.require`` or, in
native mode, when the AF_UNIX rule is needed), and ``PR_SET_PDEATHSIG``.  Memory and process caps use cgroup v2 through
``systemd-run --user --scope`` when the probe proves it works, otherwise
RLIMIT_AS / RLIMIT_NPROC (reported honestly as such).

Every probe result is cached for the life of the process; call
:func:`clear_probe_cache` to force a re-probe.
"""

from __future__ import annotations

import os
import platform
import shutil
import signal
import subprocess
import sys
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from dspy_interpreters.isolation._backend import (
    BackendCapabilities,
    LaunchPlan,
    base_policy,
    clean_env,
    dedupe_paths,
    inherited_env,
    python_argv,
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
    IsolationSpecError,
    IsolationUnsupportedError,
)

BACKEND_NAME = "linux"
LAUNCHER_OPTION = "linux.launcher"
LAUNCHERS = ("auto", "bwrap", "native")

SECCOMP_MACHINES = ("x86_64", "aarch64")
# Native mode: Landlock and a network namespace do not stop connect() to a filesystem-path Unix socket of
# the host (docker.sock, the D-Bus bus, ...); the seccomp filter denies socket(AF_UNIX) instead.
UNIX_SOCKET_DENY = "seccomp deny socket(AF_UNIX)"
NATIVE_UNIX_SOCKET_NOTE = (
    "native: socket(AF_UNIX) is denied with EPERM so host Unix sockets outside the allowlist stay "
    "unreachable; socketpair() still works"
)
NATIVE_REAPER_NOTE = (
    "native: PR_SET_PDEATHSIG ends the worker process; a helper forked by the worker then SIGKILLs the "
    "worker's process group, so guest processes survive only if they left the session (setsid)"
)
DEVICE_RW_FILES = ("/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/tty")
# Environment variables systemd-run needs to reach the user manager; scrubbed from a clean worker environment.
SYSTEMD_BUS_VARIABLES = ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
# Variable systemd-run itself adds to the scope's environment; scrubbed as well.
SYSTEMD_INVOCATION_VARIABLE = "INVOCATION_ID"

PROBE_TIMEOUT = 10.0
_PROBE_MEMORY = 64 * 1024 * 1024
_PROBE_TASKS = 64

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
SYS_LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1


# --------------------------------------------------------------------------- #
# Probes (cached)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of one machine probe.  ``value`` carries the Landlock ABI or a tool path."""

    ok: bool
    detail: str
    value: Any = None


_PROBE_CACHE: dict[str, ProbeResult] = {}


def clear_probe_cache() -> None:
    _PROBE_CACHE.clear()


def _cached(name: str, compute) -> ProbeResult:
    result = _PROBE_CACHE.get(name)
    if result is None:
        try:
            result = compute()
        except Exception as exc:  # a probe must never raise
            result = ProbeResult(False, f"{name} probe failed: {type(exc).__name__}: {exc}")
        _PROBE_CACHE[name] = result
    return result


def _run_probe(argv: list[str], *, name: str, ok_when=None) -> ProbeResult:
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=PROBE_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ProbeResult(False, f"{name} probe timed out after {PROBE_TIMEOUT:g}s")
    except OSError as exc:
        return ProbeResult(False, f"{name} probe could not start: {exc}")
    stdout = completed.stdout.decode("utf-8", "replace").strip()
    stderr = completed.stderr.decode("utf-8", "replace").strip()
    if completed.returncode != 0:
        tail = (stderr or stdout).splitlines()[-1] if (stderr or stdout) else ""
        return ProbeResult(False, f"{name} probe exited with status {completed.returncode}: {tail}".rstrip(": "))
    if ok_when is not None:
        verdict = ok_when(stdout)
        if verdict is not None:
            return ProbeResult(False, f"{name} probe: {verdict}")
    return ProbeResult(True, f"{name} works", value=argv[0])


def probe_bwrap() -> ProbeResult:
    """Can bubblewrap start a Python process here?"""

    def compute() -> ProbeResult:
        if not sys.platform.startswith("linux"):
            return ProbeResult(False, f"bwrap is Linux-only (platform {sys.platform})")
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            return ProbeResult(False, "bwrap not found on PATH")
        argv = [
            bwrap,
            "--unshare-all",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--",
            sys.executable,
            "-I",
            "-c",
            "pass",
        ]
        result = _run_probe(argv, name="bwrap")
        return ProbeResult(result.ok, result.detail, value=bwrap)

    return _cached("bwrap", compute)


def probe_landlock_abi() -> ProbeResult:
    """Landlock ABI version of the running kernel (``value``), or why it is unavailable."""

    def compute() -> ProbeResult:
        if not sys.platform.startswith("linux"):
            return ProbeResult(False, f"Landlock is Linux-only (platform {sys.platform})", value=0)
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        syscall = libc.syscall
        syscall.restype = ctypes.c_long
        abi = int(
            syscall(
                ctypes.c_long(SYS_LANDLOCK_CREATE_RULESET),
                ctypes.c_void_p(None),
                ctypes.c_size_t(0),
                ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION),
            )
        )
        if abi < 1:
            err = ctypes.get_errno()
            why = os.strerror(err) if err else "not supported"
            hint = " (kernel < 5.13 or CONFIG_SECURITY_LANDLOCK/lsm= not enabled?)"
            return ProbeResult(False, f"Landlock unavailable: {why}{hint}", value=0)
        return ProbeResult(True, f"Landlock ABI {abi}", value=abi)

    return _cached("landlock", compute)


_USERNS_PROBE_CODE = """
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
if libc.unshare(0x10000000 | 0x40000000) != 0:
    err = ctypes.get_errno()
    sys.stdout.write("EPERM" if err == 1 else os.strerror(err))
    sys.exit(1)
sys.stdout.write("ok")
"""


def _userns_reason(detail: str) -> str:
    hints = []
    try:
        with open("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") as handle:
            if handle.read().strip() == "1":
                hints.append("apparmor_restrict_unprivileged_userns=1")
    except OSError:
        pass
    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone") as handle:
            if handle.read().strip() == "0":
                hints.append("kernel.unprivileged_userns_clone=0")
    except OSError:
        pass
    try:
        with open("/proc/sys/user/max_user_namespaces") as handle:
            if handle.read().strip() == "0":
                hints.append("user.max_user_namespaces=0")
    except OSError:
        pass
    reason = "user namespaces disabled"
    if hints:
        reason += " (" + ", ".join(hints) + ")"
    return f"{reason}: {detail}" if detail else reason


def probe_userns() -> ProbeResult:
    """Can an unprivileged process call ``unshare(CLONE_NEWUSER | CLONE_NEWNET)``?"""

    def compute() -> ProbeResult:
        if not sys.platform.startswith("linux"):
            return ProbeResult(False, f"user namespaces are Linux-only (platform {sys.platform})")
        result = _run_probe([sys.executable, "-I", "-c", _USERNS_PROBE_CODE], name="unshare")
        if result.ok:
            return ProbeResult(True, "unprivileged user namespaces work")
        return ProbeResult(False, _userns_reason(result.detail))

    return _cached("userns", compute)


_CGROUP_PROBE_CODE = """
import sys
line = open("/proc/self/cgroup").read().strip().splitlines()[-1]
path = line.split(":", 2)[2]
values = []
for name in ("memory.max", "pids.max"):
    with open("/sys/fs/cgroup" + path + "/" + name) as handle:
        values.append(handle.read().strip())
sys.stdout.write(" ".join(values))
"""


def probe_systemd_run() -> ProbeResult:
    """Can ``systemd-run --user --scope`` apply MemoryMax/TasksMax to a transient scope?"""

    def compute() -> ProbeResult:
        if not sys.platform.startswith("linux"):
            return ProbeResult(False, f"systemd-run is Linux-only (platform {sys.platform})")
        systemd_run = shutil.which("systemd-run")
        if systemd_run is None:
            return ProbeResult(False, "systemd-run not found on PATH")
        expected = f"{_PROBE_MEMORY} {_PROBE_TASKS}"

        def verify(stdout: str) -> str | None:
            if stdout != expected:
                return f"cgroup limits not applied (memory.max pids.max = {stdout!r}, expected {expected!r})"
            return None

        argv = [
            systemd_run,
            "--user",
            "--scope",
            "--quiet",
            "--collect",
            "-p",
            f"MemoryMax={_PROBE_MEMORY}",
            "-p",
            f"TasksMax={_PROBE_TASKS}",
            "--",
            sys.executable,
            "-I",
            "-c",
            _CGROUP_PROBE_CODE,
        ]
        result = _run_probe(argv, name="systemd-run", ok_when=verify)
        return ProbeResult(result.ok, result.detail, value=systemd_run)

    return _cached("systemd_run", compute)


def seccomp_machine() -> str | None:
    """The seccomp architecture name when the denylist supports this CPU, else None."""
    machine = platform.machine()
    return machine if machine in SECCOMP_MACHINES else None


def _seccomp_unsupported_reason() -> str:
    return f"seccomp denylist supports x86_64 and aarch64 only, not {platform.machine()!r}"


def _native_unix_socket_reason() -> str:
    return (
        "filesystem-path Unix sockets cannot be blocked without the seccomp denylist "
        f"(x86_64 and aarch64 only, not {platform.machine()!r})"
    )


# --------------------------------------------------------------------------- #
# Pure planning helpers
# --------------------------------------------------------------------------- #


def launcher_of(spec: IsolationSpec) -> str:
    launcher = spec.backend_options.get(LAUNCHER_OPTION, "auto")
    if launcher not in LAUNCHERS:
        raise IsolationSpecError(f"{LAUNCHER_OPTION} must be one of {LAUNCHERS}, not {launcher!r}")
    return launcher


def _top_level(path: str) -> str:
    parts = path.split(os.sep)
    return os.sep + parts[1] if len(parts) > 1 and parts[1] else os.sep


def resolve_top_level_symlinks(paths: Iterable[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Rewrite paths under a symlinked top-level directory (``/lib -> usr/lib``).

    Returns ``(paths, symlinks)`` where ``symlinks`` are ``(target, link)``
    pairs to recreate inside the sandbox and ``paths`` point at the real
    locations.  Only the first path component is examined.
    """
    resolved: list[str] = []
    symlinks: list[tuple[str, str]] = []
    for path in paths:
        top = _top_level(path)
        if top != os.sep and os.path.islink(top):
            target = os.readlink(top)
            if (target, top) not in symlinks:
                symlinks.append((target, top))
            real_top = os.path.realpath(top)
            rest = path[len(top) :]
            resolved.append(real_top + rest)
        else:
            resolved.append(path)
    return resolved, symlinks


def build_bwrap_argv(
    *,
    bwrap: str,
    command: Sequence[str],
    workdir: str,
    read_paths: Sequence[str] = (),
    write_paths: Sequence[str] = (),
    private_tmp: bool = False,
    network_none: bool = False,
    host_filesystem: bool = False,
    unsetenv: Sequence[str] = (),
) -> list[str]:
    """bubblewrap command line for the worker.

    The sandbox root is an empty tmpfs remounted read-only at the end;
    ``read_paths`` are bound read-only and ``write_paths`` read-write at their
    host locations (top-level symlinks such as ``/lib -> usr/lib`` are
    recreated).  ``private_tmp`` mounts an empty tmpfs at ``/tmp`` (the session
    tmp directory is one of ``write_paths`` and ``TMPDIR`` points at it).
    ``host_filesystem`` binds ``/`` read-write instead (no allowlist requested).
    Environment variables are inherited from the launcher's environment (the
    host passes exactly the worker variables) except ``unsetenv`` names.
    """
    argv = [
        bwrap,
        "--unshare-user-try",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
    ]
    if network_none:
        argv.append("--unshare-net")
    argv += ["--die-with-parent", "--new-session"]
    if host_filesystem:
        argv += ["--bind", "/", "/", "--proc", "/proc", "--dev", "/dev"]
    else:
        reads, symlinks = resolve_top_level_symlinks(read_paths)
        writes, write_symlinks = resolve_top_level_symlinks(write_paths)
        for target, link in symlinks + [pair for pair in write_symlinks if pair not in symlinks]:
            argv += ["--symlink", target, link]
        binds = [("--ro-bind-try", path) for path in dedupe_paths(reads)]
        binds += [("--bind-try", path) for path in dedupe_paths(writes)]
        # Binds under the special mounts must come after them (a later mount shadows an earlier one).
        special = ("/proc", "/dev", "/tmp")
        late = [bind for bind in binds if _top_level(bind[1]) in special]
        for option, path in binds:
            if (option, path) not in late:
                argv += [option, path, path]
        argv += ["--proc", "/proc", "--dev", "/dev"]
        if private_tmp:
            argv += ["--tmpfs", "/tmp"]
        for option, path in late:
            argv += [option, path, path]
        if "/" not in {path for option, path in binds if option == "--bind-try"}:
            argv += ["--remount-ro", "/"]
    argv += ["--chdir", workdir]
    for name in unsetenv:
        argv += ["--unsetenv", name]
    argv.append("--")
    argv.extend(command)
    return argv


def _with_required(paths: list[str], *required: str) -> list[str]:
    """``paths`` plus every ``required`` path that is not already covered (even when it does not exist yet)."""
    result = list(paths)
    for path in required:
        covered = any(path == p or path.startswith(p.rstrip(os.sep) + os.sep) for p in result)
        if not covered:
            result.append(path)
    return result


def build_systemd_run_prefix(
    *, systemd_run: str, unit: str, memory_bytes: int | None, max_processes: int | None
) -> list[str]:
    """``systemd-run --user --scope`` prefix applying cgroup v2 memory/pids limits."""
    argv = [systemd_run, "--user", "--scope", "--quiet", "--collect", f"--unit={unit}"]
    if memory_bytes is not None:
        argv += ["-p", f"MemoryMax={memory_bytes}", "-p", "MemorySwapMax=0"]
    if max_processes is not None:
        argv += ["-p", f"TasksMax={max_processes}"]
    argv.append("--")
    return argv


def build_policy(
    spec: IsolationSpec,
    *,
    launcher: str,
    work_dir: str,
    read_paths: Sequence[str],
    write_paths: Sequence[str],
    use_cgroup: bool,
    seccomp_supported: bool = True,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Worker policy plus the ``applied`` names the host must verify.

    ``launcher`` is ``"bwrap"`` or ``"native"``.  Landlock and ``unshare_net``
    are *required* in native mode; in bwrap mode the mounts and namespaces do
    the work and Landlock is only an optional extra.  RLIMIT_AS/RLIMIT_NPROC
    are sent only when no cgroup limit is available.  In native mode with a
    files policy or ``network="none"`` the seccomp filter is required as well
    and denies ``socket(AF_UNIX)`` (see :data:`UNIX_SOCKET_DENY`).
    """
    if launcher not in ("bwrap", "native"):
        raise ValueError(f"launcher must be 'bwrap' or 'native', not {launcher!r}")
    policy = base_policy(spec, work_dir=work_dir)
    if launcher == "native":
        policy["pgroup_reaper"] = True  # bwrap tears down its pid namespace instead
    required: list[str] = ["pdeathsig"]
    limits = spec.limits
    if limits.cpu_seconds is not None:
        required.append("rlimit:cpu")
    if not use_cgroup:
        memory = limits.memory_bytes
        if memory is not None:
            policy["rlimits"]["as"] = memory
            required.append("rlimit:as")
        if limits.max_processes is not None:
            policy["rlimits"]["nproc"] = limits.max_processes
            required.append("rlimit:nproc")
    if spec.files is not None:
        landlock_required = launcher == "native"
        policy["landlock"] = {
            "required": landlock_required,
            "read": list(read_paths),
            "write": list(write_paths),
            "rw_files": list(DEVICE_RW_FILES),
        }
        if landlock_required:
            required.append("landlock")
    if spec.network.mode == "none" and launcher == "native":
        policy["unshare_net"] = {"required": True}
        required.append("unshare_net")
    nnp_required = NO_NEW_PRIVILEGES in spec.require
    policy["no_new_privs"] = {"required": nnp_required}
    if nnp_required:
        required.append("no_new_privs")
    deny_unix_sockets = launcher == "native" and (spec.files is not None or spec.network.mode == "none")
    seccomp_required = REDUCED_KERNEL_SURFACE in spec.require or deny_unix_sockets
    if seccomp_supported or seccomp_required:
        policy["seccomp"] = {"required": seccomp_required, "deny_unix_sockets": deny_unix_sockets}
    if seccomp_required:
        required.append("seccomp")
    return policy, tuple(required)


# --------------------------------------------------------------------------- #
# Backend
# --------------------------------------------------------------------------- #


class LinuxBackend:
    name = BACKEND_NAME

    # -- capabilities ------------------------------------------------------- #

    def capabilities(self) -> BackendCapabilities:
        bwrap = probe_bwrap()
        landlock = probe_landlock_abi()
        userns = probe_userns()
        cgroup = probe_systemd_run()
        machine = seccomp_machine()
        supported: dict[str, str] = {
            OWN_ADDRESS_SPACE: "separate worker process",
            WALL_TIME_CAPPED: "host deadline kills the worker",
            KILLED_WITH_HOST: "bwrap --die-with-parent + PR_SET_PDEATHSIG" if bwrap.ok else "PR_SET_PDEATHSIG",
            CPU_TIME_CAPPED: "RLIMIT_CPU",
            CLEAN_ENVIRONMENT: "explicit environment + python -I",
            NO_NEW_PRIVILEGES: "PR_SET_NO_NEW_PRIVS",
        }
        unsupported: dict[str, str] = {}
        notes: list[str] = [bwrap.detail, landlock.detail, userns.detail, cgroup.detail]
        if cgroup.ok:
            supported[MEMORY_CAPPED] = "cgroup v2 memory.max via systemd-run --user --scope"
            supported[PROCESS_COUNT_CAPPED] = "cgroup v2 pids.max via systemd-run --user --scope"
        else:
            supported[MEMORY_CAPPED] = "RLIMIT_AS"
            supported[PROCESS_COUNT_CAPPED] = "RLIMIT_NPROC"
        if bwrap.ok:
            supported[FILESYSTEM_ALLOWLIST] = "bwrap bind-mount allowlist" + (
                f" + Landlock ABI {landlock.value}" if landlock.ok else ""
            )
            supported[PRIVATE_TMP] = "TMPDIR set to the session tmp; bwrap mounts a private tmpfs at /tmp"
            supported[NO_AMBIENT_NETWORK] = "bwrap --unshare-net"
        else:
            if landlock.ok and machine is not None:
                supported[FILESYSTEM_ALLOWLIST] = f"Landlock ABI {landlock.value} + {UNIX_SOCKET_DENY}"
                supported[PRIVATE_TMP] = "TMPDIR set to the session tmp; host /tmp outside the Landlock allowlist"
            else:
                reason = f"{bwrap.detail}; {landlock.detail if not landlock.ok else _native_unix_socket_reason()}"
                unsupported[FILESYSTEM_ALLOWLIST] = reason
                unsupported[PRIVATE_TMP] = reason
            if userns.ok and machine is not None:
                supported[NO_AMBIENT_NETWORK] = f"unshare(CLONE_NEWUSER|CLONE_NEWNET) + {UNIX_SOCKET_DENY}"
            else:
                reason = userns.detail if not userns.ok else _native_unix_socket_reason()
                unsupported[NO_AMBIENT_NETWORK] = f"{bwrap.detail}; {reason}"
        if machine is not None:
            supported[REDUCED_KERNEL_SURFACE] = f"seccomp-bpf denylist ({machine})"
        else:
            unsupported[REDUCED_KERNEL_SURFACE] = _seccomp_unsupported_reason()
        return BackendCapabilities(
            name=self.name,
            platform=sys.platform,
            supported=supported,
            unsupported=unsupported,
            notes=tuple(notes),
        )

    # -- planning ------------------------------------------------------------ #

    def _choose_launcher(self, spec: IsolationSpec) -> tuple[str, dict[str, ProbeResult]]:
        requested = launcher_of(spec)
        probes = {"bwrap": probe_bwrap(), "landlock": probe_landlock_abi(), "userns": probe_userns()}
        wants_fs = spec.files is not None
        wants_net = spec.network.mode == "none"
        guarantees = spec.guarantees()

        def native_unmet() -> dict[str, str]:
            unmet: dict[str, str] = {}
            no_seccomp = seccomp_machine() is None
            if wants_fs and (not probes["landlock"].ok or no_seccomp):
                reason = probes["landlock"].detail if not probes["landlock"].ok else _native_unix_socket_reason()
                unmet[FILESYSTEM_ALLOWLIST] = reason
                if PRIVATE_TMP in guarantees:
                    unmet[PRIVATE_TMP] = reason
            if wants_net and (not probes["userns"].ok or no_seccomp):
                unmet[NO_AMBIENT_NETWORK] = (
                    probes["userns"].detail if not probes["userns"].ok else _native_unix_socket_reason()
                )
            return unmet

        if requested == "bwrap":
            if not probes["bwrap"].ok:
                reason = f"bwrap requested: {probes['bwrap'].detail}"
                raise IsolationUnsupportedError({LAUNCHER_OPTION: reason}, self.name)
            return "bwrap", probes
        if requested == "native":
            unmet = native_unmet()
            if unmet:
                raise IsolationUnsupportedError(unmet, self.name)
            return "native", probes
        if probes["bwrap"].ok:
            return "bwrap", probes
        unmet = native_unmet()
        if unmet:
            raise IsolationUnsupportedError(
                {name: f"{probes['bwrap'].detail}; {reason}" for name, reason in unmet.items()}, self.name
            )
        return "native", probes

    def plan(self, spec: IsolationSpec, *, python: str, worker_path: str, session_dir: str) -> LaunchPlan:
        launcher, probes = self._choose_launcher(spec)
        if not os.path.isabs(python):
            python = shutil.which(python) or python
        machine = seccomp_machine()
        if REDUCED_KERNEL_SURFACE in spec.require and machine is None:
            raise IsolationUnsupportedError({REDUCED_KERNEL_SURFACE: _seccomp_unsupported_reason()}, self.name)
        session = session_paths(session_dir)
        bootstrap_dir = session["bootstrap"]
        work_dir = session["work"]
        session_tmp = session["tmp"]
        files = spec.files
        if files is not None and files.workdir is not None:
            work_dir = os.path.abspath(files.workdir)
        private_tmp = files is not None and files.private_tmp
        limits = spec.limits
        wants_cgroup = limits.memory is not None or limits.max_processes is not None
        cgroup = probe_systemd_run() if wants_cgroup else None
        use_cgroup = bool(cgroup is not None and cgroup.ok)
        notes: list[str] = [f"launcher: {launcher}"]

        # -- allowlists (host view) --
        user_read = list(files.read) if files is not None else []
        user_write = list(files.write) if files is not None else []
        with_runtime = files is None or files.include_runtime
        runtime = runtime_read_paths(python) if with_runtime else []
        system = list(system_read_paths("linux")) if with_runtime else []
        # User paths are kept even when they do not exist yet; the mounts and rules skip missing paths at start.
        read_paths = _with_required(dedupe_paths([*runtime, *system]), *map(os.path.abspath, user_read), bootstrap_dir)
        write_paths = _with_required([], *map(os.path.abspath, user_write), work_dir, session_tmp)

        # -- environment --
        if spec.env.mode == "clean":
            worker_env = clean_env(spec, tmp_dir=session_tmp, work_dir=work_dir, platform="linux")
        else:
            worker_env = inherited_env(spec, tmp_dir=session_tmp)
        launch_env = dict(worker_env)
        scrub: list[str] = []
        if use_cgroup:
            for name in SYSTEMD_BUS_VARIABLES:
                if name in os.environ and name not in launch_env:
                    launch_env[name] = os.environ[name]
                    if spec.env.mode == "clean":
                        scrub.append(name)
            if spec.env.mode == "clean" and SYSTEMD_INVOCATION_VARIABLE not in worker_env:
                scrub.append(SYSTEMD_INVOCATION_VARIABLE)

        # -- command --
        command = python_argv(python, worker_path, spec)
        if launcher == "bwrap":
            argv = build_bwrap_argv(
                bwrap=probes["bwrap"].value,
                command=command,
                workdir=work_dir,
                read_paths=read_paths,
                write_paths=write_paths,
                private_tmp=private_tmp,
                network_none=spec.network.mode == "none",
                host_filesystem=files is None,
                unsetenv=scrub,
            )
            # Landlock is only an extra layer here: the sandbox root already contains nothing but the binds, so
            # reading it is allowed (os.listdir("/"), /proc, /dev) while writes stay limited to the listed paths.
            policy_read = [*read_paths, "/"]
            policy_write = [*write_paths, "/dev/shm", *(["/tmp"] if private_tmp else [])]
        else:
            argv = list(command)
            if scrub:
                names = ",".join(repr(name) for name in scrub)
                trampoline = (
                    f"import os,sys\nfor k in ({names},):\n os.environ.pop(k,None)\nos.execv(sys.argv[1],sys.argv[1:])"
                )
                argv = [python, "-I", "-c", trampoline, *command]
            policy_read = [*read_paths, "/proc/self"]
            policy_write = list(write_paths)
        policy, required = build_policy(
            spec,
            launcher=launcher,
            work_dir=work_dir,
            read_paths=policy_read,
            write_paths=policy_write,
            use_cgroup=use_cgroup,
            seccomp_supported=machine is not None,
        )
        state: dict[str, Any] = {"launcher": launcher}
        if use_cgroup:
            unit = f"dspy-interp-{uuid.uuid4().hex[:12]}.scope"
            state["systemd_unit"] = unit
            argv = [
                *build_systemd_run_prefix(
                    systemd_run=probe_systemd_run().value,
                    unit=unit,
                    memory_bytes=limits.memory_bytes,
                    max_processes=limits.max_processes,
                ),
                *argv,
            ]
            notes.append(f"cgroup scope: {unit}")

        # -- report --
        guarantees = universal_guarantees(spec)
        landlock_abi = probes["landlock"].value if probes["landlock"].ok else None
        if launcher == "bwrap":
            guarantees[KILLED_WITH_HOST] = "bwrap --die-with-parent + PR_SET_PDEATHSIG"
            if files is not None:
                mechanism = "bwrap bind-mount allowlist"
                if landlock_abi:
                    mechanism += f" + Landlock ABI {landlock_abi}"
                guarantees[FILESYSTEM_ALLOWLIST] = mechanism
                if private_tmp:
                    guarantees[PRIVATE_TMP] = "TMPDIR set to the session tmp; bwrap mounts a private tmpfs at /tmp"
            if spec.network.mode == "none":
                guarantees[NO_AMBIENT_NETWORK] = "bwrap --unshare-net"
            notes.append("bwrap: fresh /proc and /dev; new user, pid, ipc, uts namespaces; sandbox root read-only")
        else:
            guarantees[KILLED_WITH_HOST] = "PR_SET_PDEATHSIG"
            notes.append(NATIVE_REAPER_NOTE)
            if files is not None:
                guarantees[FILESYSTEM_ALLOWLIST] = f"Landlock ABI {landlock_abi} + {UNIX_SOCKET_DENY}"
                if private_tmp:
                    guarantees[PRIVATE_TMP] = "TMPDIR set to the session tmp; host /tmp outside the Landlock allowlist"
                notes.append("native: the worker may read its own /proc/self")
            if spec.network.mode == "none":
                guarantees[NO_AMBIENT_NETWORK] = f"unshare(CLONE_NEWUSER|CLONE_NEWNET) + {UNIX_SOCKET_DENY}"
            if policy["seccomp"] is not None and policy["seccomp"]["deny_unix_sockets"]:
                notes.append(NATIVE_UNIX_SOCKET_NOTE)
        if limits.memory is not None:
            guarantees[MEMORY_CAPPED] = (
                "cgroup v2 memory.max via systemd-run --user --scope" if use_cgroup else "RLIMIT_AS"
            )
        if limits.max_processes is not None:
            if use_cgroup:
                guarantees[PROCESS_COUNT_CAPPED] = "cgroup v2 pids.max via systemd-run --user --scope"
            else:
                guarantees[PROCESS_COUNT_CAPPED] = "RLIMIT_NPROC"
                if launcher == "native" and spec.network.mode != "none":
                    notes.append("RLIMIT_NPROC counts every process of this user (no user namespace)")
        if wants_cgroup and cgroup is not None and not cgroup.ok:
            notes.append(f"cgroup limits unavailable ({cgroup.detail}); using rlimits")
        if limits.cpu_seconds is not None:
            guarantees[CPU_TIME_CAPPED] = "RLIMIT_CPU"
        if spec.env.mode == "clean":
            guarantees[CLEAN_ENVIRONMENT] = "explicit environment + python -I"
            if scrub:
                notes.append("systemd-run variables (" + ", ".join(scrub) + ") removed before the worker starts")
        guarantees[NO_NEW_PRIVILEGES] = "PR_SET_NO_NEW_PRIVS"
        if machine is not None:
            guarantees[REDUCED_KERNEL_SURFACE] = f"seccomp-bpf denylist ({machine})"
        report = IsolationReport(
            backend=self.name,
            platform=sys.platform,
            requested=spec.guarantees(),
            guarantees=guarantees,
            notes=tuple(notes),
        )
        return LaunchPlan(
            argv=argv,
            env=launch_env,
            cwd=work_dir,
            policy=policy,
            report=report,
            popen_kwargs={"start_new_session": True},
            required_applied=required,
            state=state,
        )

    # -- process hooks ------------------------------------------------------- #

    def attach(self, process: subprocess.Popen[bytes], plan: LaunchPlan) -> None:
        return None

    def kill(self, process: subprocess.Popen[bytes], plan: LaunchPlan) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.kill()
        except OSError:
            pass
        unit = plan.state.get("systemd_unit")
        if unit:
            systemctl = shutil.which("systemctl")
            if systemctl is not None:
                try:
                    subprocess.run(
                        [systemctl, "--user", "kill", "--signal=KILL", unit],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                        check=False,
                    )
                except (OSError, subprocess.SubprocessError):
                    pass


__all__ = [
    "DEVICE_RW_FILES",
    "LAUNCHERS",
    "LAUNCHER_OPTION",
    "SECCOMP_MACHINES",
    "UNIX_SOCKET_DENY",
    "LinuxBackend",
    "ProbeResult",
    "build_bwrap_argv",
    "build_policy",
    "build_systemd_run_prefix",
    "clear_probe_cache",
    "launcher_of",
    "probe_bwrap",
    "probe_landlock_abi",
    "probe_systemd_run",
    "probe_userns",
    "resolve_top_level_symlinks",
    "seccomp_machine",
]
