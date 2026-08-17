"""Subprocess worker for ``LocalInterpreter(mode="subprocess")``.

This file is copied into a per-session bootstrap directory and started as
``python [-I] -u worker.py``.  It is self-contained: standard library plus
``ctypes`` only, importable on every operating system, and safe to run as a
script.

Protocol (line-delimited JSON, UTF-8, ``separators=(",", ":")``) over the
inherited stdin/stdout, which are moved to private high file descriptors before
any guest code runs.  Guest writes to fd 1 land on stderr and cannot forge
frames.

The first message must be a *policy*.  The worker applies it to itself in a
fixed order (umask, chdir, rlimits, die_with_parent, landlock, unshare_net,
no_new_privs, seccomp, then the optional process-group reaper), collecting
``applied`` names and ``skipped`` reasons,
then answers ``{"type": "ready", ...}``.  A failing step never crashes the
worker: the host decides what a skipped item means.

Then it serves ``execute`` / ``shutdown`` with the same result shapes as the
Modal worker (``execution_result`` kinds ``final``, ``syntax``,
``execution_error``, ``result``; ``tool_request`` / ``tool_response``;
``terminal_error``).

Audit reference for the seccomp denylist: :data:`DENIED_SYSCALLS` (name ->
number per architecture, answered with ``EPERM``), :data:`CLONE3_NR`
(answered with ``ENOSYS`` so glibc falls back to ``clone``), and
:data:`CLONE_NR` (``clone`` with ``CLONE_NEWUSER`` in its flags is answered
with ``EPERM``).
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import keyword
import os
import platform
import sys
import threading
import time
import uuid

try:  # pragma: no cover - ctypes can be missing on exotic builds
    import ctypes
except Exception:  # pragma: no cover
    ctypes = None  # type: ignore[assignment]

try:
    import resource
except ImportError:  # Windows
    resource = None  # type: ignore[assignment]

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None  # type: ignore[assignment]

# --------------------------------------------------------------------------- #
# Constants (Linux ratchet)
# --------------------------------------------------------------------------- #

PR_SET_PDEATHSIG = 1
PR_SET_SECCOMP = 22
PR_SET_NO_NEW_PRIVS = 38
SECCOMP_MODE_FILTER = 2

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
_USERNS_MAP_FILES = ("/proc/self/setgroups", "/proc/self/uid_map", "/proc/self/gid_map")

# Landlock
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1

LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13  # ABI 2
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14  # ABI 3
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15  # ABI 5

_LANDLOCK_ABI1_FS = (1 << 13) - 1
_LANDLOCK_FS_BY_ABI = {
    1: _LANDLOCK_ABI1_FS,
    2: _LANDLOCK_ABI1_FS | LANDLOCK_ACCESS_FS_REFER,
    3: _LANDLOCK_ABI1_FS | LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE,
    4: _LANDLOCK_ABI1_FS | LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE,
    5: _LANDLOCK_ABI1_FS | LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV,
}
# Access bits that are valid for a rule on a non-directory file.
_LANDLOCK_FILE_ACCESS = (
    LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_TRUNCATE
    | LANDLOCK_ACCESS_FS_IOCTL_DEV
)

# seccomp
AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
X32_SYSCALL_BIT = 0x40000000
EPERM = 1
ENOSYS = 38

BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_JMP_JGE_K = 0x35
BPF_JMP_JSET_K = 0x45
BPF_RET_K = 0x06

# Syscalls answered with EPERM.  ``None`` means the syscall does not exist on that architecture.
_DENYLIST: dict[str, tuple[int | None, int | None]] = {
    "ptrace": (101, 117),
    "mount": (165, 40),
    "umount2": (166, 39),
    "pivot_root": (155, 41),
    "swapon": (167, 224),
    "swapoff": (168, 225),
    "reboot": (169, 142),
    "kexec_load": (246, 104),
    "kexec_file_load": (320, 294),
    "init_module": (175, 105),
    "finit_module": (313, 273),
    "delete_module": (176, 106),
    "keyctl": (250, 219),
    "add_key": (248, 217),
    "request_key": (249, 218),
    "bpf": (321, 280),
    "perf_event_open": (298, 241),
    "userfaultfd": (323, 282),
    "unshare": (272, 97),
    "setns": (308, 268),
    "personality": (135, 92),
    "process_vm_readv": (310, 270),
    "process_vm_writev": (311, 271),
    "open_by_handle_at": (304, 265),
    "acct": (163, 89),
    "settimeofday": (164, 170),
    "clock_settime": (227, 112),
    "adjtimex": (159, 171),
    "quotactl": (179, 60),
    "chroot": (161, 51),
    "mknod": (133, None),
    "mknodat": (259, 33),
    "io_uring_setup": (425, 425),
    "io_uring_enter": (426, 426),
    "io_uring_register": (427, 427),
    "open_tree": (428, 428),
    "move_mount": (429, 429),
    "fsopen": (430, 430),
    "fsconfig": (431, 431),
    "fsmount": (432, 432),
    "fspick": (433, 433),
    "pidfd_getfd": (438, 438),
    "mount_setattr": (442, 442),
    "kcmp": (312, 272),
    "ioperm": (173, None),
    "iopl": (172, None),
    "vhangup": (153, 58),
}
DENIED_SYSCALLS: dict[str, dict[str, int]] = {
    "x86_64": {name: nrs[0] for name, nrs in _DENYLIST.items() if nrs[0] is not None},
    "aarch64": {name: nrs[1] for name, nrs in _DENYLIST.items() if nrs[1] is not None},
}
CLONE3_NR = 435  # -> ENOSYS (glibc falls back to clone)
CLONE_NR = {"x86_64": 56, "aarch64": 220}  # clone with CLONE_NEWUSER -> EPERM
SOCKET_NR = {"x86_64": 41, "aarch64": 198}  # socket(AF_UNIX, ...) -> EPERM when the policy asks for it
AF_UNIX = 1

_INITIAL_PPID = os.getppid()
_WORKER_PID = os.getpid()

# --------------------------------------------------------------------------- #
# Protocol transport
# --------------------------------------------------------------------------- #


class ProtocolError(RuntimeError):
    pass


class Submission(BaseException):
    def __init__(self, value):
        self.value = value


class HostToolError(RuntimeError):
    pass


class Transport:
    """Line-delimited JSON over two private file descriptors."""

    def __init__(self, in_fd: int, out_fd: int) -> None:
        self._in_fd = in_fd
        self._out_fd = out_fd
        self._reader = open(in_fd, "rb", buffering=65536, closefd=False)

    def send(self, message) -> None:
        if os.getpid() != _WORKER_PID:
            # A process forked by guest code (os.fork without exec) must never speak the protocol:
            # it would answer the host in place of the worker and shift every later result.
            os._exit(0)
        data = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(self._out_fd, view)
            view = view[written:]

    def receive(self):
        line = self._reader.readline()
        if not line:
            raise EOFError("host closed the interpreter protocol")
        message = json.loads(line.decode("utf-8"))
        if not isinstance(message, dict):
            raise ProtocolError("host sent a non-object message")
        return message


def _move_fd_high(fd: int) -> int:
    """Duplicate ``fd`` to a private, non-inheritable descriptor (>= 100 where fcntl exists)."""
    if fcntl is not None:
        try:
            new_fd = fcntl.fcntl(fd, getattr(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD), 100)
            os.set_inheritable(new_fd, False)
            return new_fd
        except Exception:
            pass
    new_fd = os.dup(fd)
    os.set_inheritable(new_fd, False)
    return new_fd


def take_protocol_fds() -> Transport:
    """Move fd 0/1 to private descriptors, then point fd 0 at devnull and fd 1 at fd 2."""
    in_fd = _move_fd_high(0)
    out_fd = _move_fd_high(1)
    if msvcrt is not None:  # binary mode: no CRLF translation on the protocol pipes
        for fd in (in_fd, out_fd):
            try:
                msvcrt.setmode(fd, os.O_BINARY)  # type: ignore[attr-defined]
            except Exception:
                pass
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    try:
        os.dup2(2, 1)
    except OSError:  # fd 2 closed: park fd 1 on devnull instead
        sink = os.open(os.devnull, os.O_WRONLY)
        os.dup2(sink, 1)
        os.close(sink)
    try:
        sys.stdout.flush()
    except Exception:
        pass
    return Transport(in_fd, out_fd)


# --------------------------------------------------------------------------- #
# Ratchet helpers
# --------------------------------------------------------------------------- #


def _libc():
    if ctypes is None:
        raise RuntimeError("ctypes unavailable")
    return ctypes.CDLL(None, use_errno=True)


def _errno_text(err: int) -> str:
    return f"{os.strerror(err)} (errno {err})"


def _reason(exc: BaseException) -> str:
    text = str(exc)
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _prctl(option: int, arg2: int = 0, arg3: int = 0, arg4: int = 0, arg5: int = 0) -> int:
    libc = _libc()
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    result = prctl(option, arg2, arg3, arg4, arg5)
    if result != 0:
        raise OSError(ctypes.get_errno(), _errno_text(ctypes.get_errno()))
    return result


def _apply_umask() -> None:
    os.umask(0o077)


def _apply_chdir(path: str) -> None:
    os.chdir(path)


def _apply_rlimits(rlimits, applied: list, skipped: dict) -> None:
    for name, value in rlimits.items():
        key = f"rlimit:{name}"
        try:
            if resource is None:
                raise RuntimeError("no resource module")
            constant = getattr(resource, "RLIMIT_" + str(name).upper(), None)
            if constant is None:
                raise RuntimeError("unknown rlimit")
            value = int(value)
            _soft, hard = resource.getrlimit(constant)
            if hard != resource.RLIM_INFINITY and hard < value:
                value = hard
            resource.setrlimit(constant, (value, value))
            applied.append(key)
        except Exception as exc:
            skipped[key] = _reason(exc)


def _apply_pdeathsig() -> None:
    import signal

    if not sys.platform.startswith("linux"):
        raise RuntimeError(f"PR_SET_PDEATHSIG unavailable on {sys.platform}")
    _prctl(PR_SET_PDEATHSIG, int(signal.SIGKILL))
    # The parent may have died between our spawn and the prctl call: an orphan is
    # reparented, so its ppid changes.  Do not test for ppid == 1: under
    # ``bwrap --unshare-pid`` (or when the host itself is pid 1 in a container)
    # the legitimate parent *is* pid 1.
    if os.getppid() != _INITIAL_PPID:
        os._exit(0)


def _start_ppid_watchdog() -> None:
    """Poll the parent every 0.5 s and exit when it disappears (POSIX and Windows)."""
    waiter = None
    if sys.platform == "win32" and ctypes is not None:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
            SYNCHRONIZE = 0x00100000
            handle = kernel32.OpenProcess(SYNCHRONIZE, False, _INITIAL_PPID)
            if handle:

                def waiter():
                    while True:
                        if kernel32.WaitForSingleObject(handle, 500) == 0:  # WAIT_OBJECT_0
                            os._exit(0)

        except Exception:
            waiter = None
    if waiter is None:
        # Bind the callables now: guest code shares this process and could rebind os.getppid / os._exit.
        def waiter(_getppid=os.getppid, _exit=os._exit, _sleep=time.sleep, _ppid=_INITIAL_PPID):
            while True:
                _sleep(0.5)
                if _getppid() != _ppid:
                    _exit(0)

    thread = threading.Thread(target=waiter, name="ppid-watchdog", daemon=True)
    thread.start()


def _start_pgroup_reaper() -> None:
    """Fork a helper that SIGKILLs the worker's process group once the worker itself is gone.

    ``PR_SET_PDEATHSIG`` and the ppid watchdog end only the worker process; the
    processes guest code spawned would survive an abrupt host death.  The helper
    sits in the same process group (created for the worker with
    ``start_new_session=True``), polls its parent, and calls ``killpg(0,
    SIGKILL)`` when the worker disappears.  Guests that call ``setsid()``
    leave the group and are not covered.
    """
    import signal

    if not hasattr(os, "fork") or not hasattr(os, "killpg"):
        raise RuntimeError(f"fork/killpg unavailable on {sys.platform}")
    if os.getsid(0) != os.getpgrp():
        raise RuntimeError("worker is not in a session of its own; refusing to reap a shared process group")
    worker_pid = os.getpid()
    pid = os.fork()
    if pid != 0:
        return
    try:  # child: never returns, never runs the worker code
        try:
            limit = int(resource.getrlimit(resource.RLIMIT_NOFILE)[0]) if resource is not None else 1024
        except Exception:
            limit = 1024
        os.closerange(0, max(3, min(limit, 65536)))
        while os.getppid() == worker_pid:
            time.sleep(0.5)
        os.killpg(0, signal.SIGKILL)
    finally:
        os._exit(0)


def _apply_no_new_privs() -> None:
    if not sys.platform.startswith("linux"):
        raise RuntimeError(f"PR_SET_NO_NEW_PRIVS unavailable on {sys.platform}")
    _prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)


def _landlock_abi(libc) -> int:
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    abi = syscall(
        ctypes.c_long(SYS_LANDLOCK_CREATE_RULESET),
        ctypes.c_void_p(None),
        ctypes.c_size_t(0),
        ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION),
    )
    if abi < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"landlock unavailable: {_errno_text(err)}")
    return int(abi)


def _apply_landlock(policy) -> str:
    if not sys.platform.startswith("linux"):
        raise RuntimeError(f"Landlock unavailable on {sys.platform}")
    libc = _libc()
    abi = _landlock_abi(libc)
    if abi < 1:
        raise RuntimeError(f"Landlock ABI {abi} unsupported")
    handled = _LANDLOCK_FS_BY_ABI.get(abi, _LANDLOCK_FS_BY_ABI[5] if abi > 5 else _LANDLOCK_ABI1_FS)

    class RulesetAttr(ctypes.Structure):
        _fields_ = (("handled_access_fs", ctypes.c_uint64),)

    class PathBeneathAttr(ctypes.Structure):
        _pack_ = 1
        _fields_ = (("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32))

    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    attr = RulesetAttr(handled)
    ruleset_fd = syscall(
        ctypes.c_long(SYS_LANDLOCK_CREATE_RULESET),
        ctypes.byref(attr),
        ctypes.c_size_t(ctypes.sizeof(attr)),
        ctypes.c_uint32(0),
    )
    if ruleset_fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"landlock_create_ruleset failed: {_errno_text(err)}")
    ruleset_fd = int(ruleset_fd)
    try:
        read_access = (
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE
        ) & handled
        write_access = handled
        rw_file_access = (
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_IOCTL_DEV
        ) & handled
        groups = (
            (policy.get("read") or [], read_access),
            (policy.get("write") or [], write_access),
            (policy.get("rw_files") or [], rw_file_access),
        )
        for paths, access in groups:
            for path in paths:
                if not isinstance(path, str) or not path:
                    continue
                try:
                    parent_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
                except OSError:
                    continue  # missing paths are skipped silently
                try:
                    allowed = access
                    if not os.path.isdir(path):
                        allowed &= _LANDLOCK_FILE_ACCESS
                    if not allowed:
                        continue
                    rule = PathBeneathAttr(allowed, parent_fd)
                    result = syscall(
                        ctypes.c_long(SYS_LANDLOCK_ADD_RULE),
                        ctypes.c_int(ruleset_fd),
                        ctypes.c_int(LANDLOCK_RULE_PATH_BENEATH),
                        ctypes.byref(rule),
                        ctypes.c_uint32(0),
                    )
                    if result != 0:
                        err = ctypes.get_errno()
                        raise OSError(err, f"landlock_add_rule({path}) failed: {_errno_text(err)}")
                finally:
                    os.close(parent_fd)
        _prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        result = syscall(ctypes.c_long(SYS_LANDLOCK_RESTRICT_SELF), ctypes.c_int(ruleset_fd), ctypes.c_uint32(0))
        if result != 0:
            err = ctypes.get_errno()
            raise OSError(err, f"landlock_restrict_self failed: {_errno_text(err)}")
    finally:
        os.close(ruleset_fd)
    return f"landlock:abi{abi}"


def _apply_unshare_net() -> None:
    if not sys.platform.startswith("linux"):
        raise RuntimeError(f"unshare unavailable on {sys.platform}")
    libc = _libc()
    unshare = libc.unshare
    unshare.restype = ctypes.c_int
    unshare.argtypes = [ctypes.c_int]
    uid, gid = os.getuid(), os.getgid()  # before unshare: afterwards they read as the overflow id
    if unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"unshare(CLONE_NEWUSER|CLONE_NEWNET) failed: {_errno_text(err)}")
    for path, text in zip(_USERNS_MAP_FILES, ("deny", f"{uid} {uid} 1", f"{gid} {gid} 1"), strict=True):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
            try:
                os.write(fd, text.encode("ascii"))
            finally:
                os.close(fd)
        except OSError:
            pass  # best effort


def _bpf(code: int, k: int, jt: int = 0, jf: int = 0) -> tuple[int, int, int, int]:
    return (code, jt, jf, k & 0xFFFFFFFF)


def build_seccomp_program(machine: str, deny_unix_sockets: bool = False) -> list[tuple[int, int, int, int]]:
    """Return the classic BPF denylist for ``machine`` as (code, jt, jf, k) tuples.

    With ``deny_unix_sockets`` the program also answers ``socket(AF_UNIX, ...)``
    with ``EPERM``: neither Landlock nor a network namespace stops ``connect()``
    to a filesystem-path Unix socket of the host (``/var/run/docker.sock``, the
    D-Bus session bus, ...).  ``socketpair()`` is a separate syscall and stays
    allowed.
    """
    arch = AUDIT_ARCH.get(machine)
    if arch is None:
        raise RuntimeError(f"unsupported architecture {machine!r}")
    program = [
        _bpf(BPF_LD_W_ABS, 4),  # A = arch
        _bpf(BPF_JMP_JEQ_K, arch, 1, 0),
        _bpf(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        _bpf(BPF_LD_W_ABS, 0),  # A = nr
    ]
    if machine == "x86_64":
        program.append(_bpf(BPF_JMP_JGE_K, X32_SYSCALL_BIT, 0, 1))
        program.append(_bpf(BPF_RET_K, SECCOMP_RET_KILL_PROCESS))
    for _name, nr in sorted(DENIED_SYSCALLS[machine].items(), key=lambda item: item[1]):
        program.append(_bpf(BPF_JMP_JEQ_K, nr, 0, 1))
        program.append(_bpf(BPF_RET_K, SECCOMP_RET_ERRNO | EPERM))
    program.append(_bpf(BPF_JMP_JEQ_K, CLONE3_NR, 0, 1))
    program.append(_bpf(BPF_RET_K, SECCOMP_RET_ERRNO | ENOSYS))
    program.append(_bpf(BPF_JMP_JEQ_K, CLONE_NR[machine], 0, 3))
    program.append(_bpf(BPF_LD_W_ABS, 16))  # A = low 32 bits of arg0 (clone flags)
    program.append(_bpf(BPF_JMP_JSET_K, CLONE_NEWUSER, 0, 1))
    program.append(_bpf(BPF_RET_K, SECCOMP_RET_ERRNO | EPERM))
    if deny_unix_sockets:
        program.append(_bpf(BPF_LD_W_ABS, 0))  # A = nr again (the clone check loaded arg0)
        program.append(_bpf(BPF_JMP_JEQ_K, SOCKET_NR[machine], 0, 3))
        program.append(_bpf(BPF_LD_W_ABS, 16))  # A = low 32 bits of arg0 (socket domain)
        program.append(_bpf(BPF_JMP_JEQ_K, AF_UNIX, 0, 1))
        program.append(_bpf(BPF_RET_K, SECCOMP_RET_ERRNO | EPERM))
    program.append(_bpf(BPF_RET_K, SECCOMP_RET_ALLOW))
    return program


def _apply_seccomp(policy=None) -> str:
    if not sys.platform.startswith("linux"):
        raise RuntimeError(f"seccomp unavailable on {sys.platform}")
    machine = platform.machine()
    if machine not in AUDIT_ARCH:
        raise RuntimeError(f"unsupported architecture {machine!r}")
    deny_unix_sockets = bool(isinstance(policy, dict) and policy.get("deny_unix_sockets"))
    program = build_seccomp_program(machine, deny_unix_sockets=deny_unix_sockets)
    if len(program) >= 4096:
        raise RuntimeError("seccomp program too large")

    class SockFilter(ctypes.Structure):
        _fields_ = (("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32))

    class SockFprog(ctypes.Structure):
        _fields_ = (("len", ctypes.c_uint16), ("filter", ctypes.POINTER(SockFilter)))

    instructions = (SockFilter * len(program))()
    for index, (code, jt, jf, k) in enumerate(program):
        instructions[index] = SockFilter(code, jt, jf, k)
    prog = SockFprog(len(program), instructions)
    _prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    _prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(prog), 0, 0)
    return f"seccomp:{machine}"


def apply_policy(policy) -> tuple[list, dict]:
    """Apply the policy in the fixed order.  Never raises."""
    applied: list = []
    skipped: dict = {}

    def step(name: str, func, *args) -> None:
        try:
            result = func(*args)
            applied.append(result if isinstance(result, str) else name)
        except BaseException as exc:
            skipped[name] = _reason(exc)

    step("umask", _apply_umask)
    if policy.get("chdir") is not None:
        step("chdir", _apply_chdir, policy["chdir"])
    rlimits = policy.get("rlimits")
    if isinstance(rlimits, dict):
        _apply_rlimits(rlimits, applied, skipped)
    want_watchdog = False
    if policy.get("die_with_parent"):
        step("pdeathsig", _apply_pdeathsig)
        want_watchdog = "pdeathsig" not in applied
    if isinstance(policy.get("landlock"), dict):
        landlock = dict(policy["landlock"])
        if isinstance(policy.get("unshare_net"), dict):
            # The later unshare_net step maps our uid/gid through these files; Landlock would deny the writes.
            landlock["rw_files"] = list(landlock.get("rw_files") or []) + list(_USERNS_MAP_FILES)
        step("landlock", _apply_landlock, landlock)
    if isinstance(policy.get("unshare_net"), dict):
        step("unshare_net", _apply_unshare_net)
    if isinstance(policy.get("no_new_privs"), dict):
        step("no_new_privs", _apply_no_new_privs)
    if isinstance(policy.get("seccomp"), dict):
        step("seccomp", _apply_seccomp, policy["seccomp"])
    # A forked helper (no threads yet) that kills the worker's process group when the worker dies.
    if policy.get("die_with_parent") and policy.get("pgroup_reaper"):
        step("pgroup_reaper", _start_pgroup_reaper)
    # Threads only after the ratchet (unshare needs a single-threaded process).
    if want_watchdog:
        step("ppid_watchdog", _start_ppid_watchdog)
    return applied, skipped


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #


class Session:
    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.namespace = {"__builtins__": __builtins__}
        self.capabilities: set = set()
        self.output_fields = None

    # -- host tools ---------------------------------------------------------- #

    def call_tool(self, name, *args, **kwargs):
        request_id = uuid.uuid4().hex
        self.transport.send({"type": "tool_request", "id": request_id, "name": name, "args": args, "kwargs": kwargs})
        response = self.transport.receive()
        if response.get("type") != "tool_response" or response.get("id") != request_id:
            raise RuntimeError("mismatched host-tool response")
        if not response.get("ok"):
            raise HostToolError(response.get("error"))
        return response.get("value")

    def bind(self, tool_names, fields) -> None:
        for name in tool_names:
            if not isinstance(name, str) or not name.isidentifier() or keyword.iskeyword(name) or name == "SUBMIT":
                raise ProtocolError(f"invalid tool name: {name!r}")
        if fields is not None:
            names = [field.get("name") for field in fields]
            if any(not isinstance(n, str) or not n.isidentifier() or keyword.iskeyword(n) for n in names):
                raise ProtocolError("output field names must be identifiers")
            if len(names) != len(set(names)):
                raise ProtocolError("output field names must be unique")
        for old_name in self.capabilities:
            self.namespace.pop(old_name, None)
        self.namespace.pop("SUBMIT", None)
        self.capabilities = set(tool_names)
        self.output_fields = fields
        for tool_name in tool_names:

            def tool(*args, __name=tool_name, **kwargs):
                return self.call_tool(__name, *args, **kwargs)

            tool.__name__ = tool_name
            tool.__qualname__ = tool_name
            self.namespace[tool_name] = tool

        def submit(*args, **kwargs):
            if self.output_fields is None:
                if len(args) != 1 or kwargs:
                    raise TypeError("SUBMIT requires one output value")
                value = {"output": args[0]}
            else:
                names = [field["name"] for field in self.output_fields]
                if args and kwargs:
                    raise TypeError("SUBMIT accepts positional or keyword values, not both")
                value = dict(zip(names, args, strict=False)) if args else dict(kwargs)
                if set(value) != set(names) or len(args) > len(names):
                    raise TypeError("SUBMIT fields do not match the configured output fields")
            raise Submission(value)

        submit.__name__ = "SUBMIT"
        self.namespace["SUBMIT"] = submit

    # -- execute ------------------------------------------------------------- #

    def execute(self, request):
        self.bind(request.get("tools") or [], request.get("output_fields"))
        variables = request.get("variables") or {}
        if not isinstance(variables, dict):
            raise ProtocolError("variables must be an object")
        self.namespace.update(variables)
        code = request.get("code")
        if not isinstance(code, str):
            raise ProtocolError("code must be a string")
        captured = io.StringIO()
        try:
            tree = ast.parse(code, mode="exec")
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                value = None
                if tree.body and isinstance(tree.body[-1], ast.Expr):
                    prefix = ast.Module(body=tree.body[:-1], type_ignores=[])
                    exec(compile(prefix, "<interpreter>", "exec"), self.namespace)
                    value = eval(compile(ast.Expression(tree.body[-1].value), "<interpreter>", "eval"), self.namespace)
                else:
                    exec(compile(tree, "<interpreter>", "exec"), self.namespace)
        except Submission as submitted:
            return {"type": "execution_result", "kind": "final", "value": _jsonable(submitted.value)}
        except SyntaxError as error:
            return {"type": "execution_result", "kind": "syntax", "error": str(error)}
        except BaseException as error:  # KeyboardInterrupt, GeneratorExit, ... must not end the session
            return {"type": "execution_result", "kind": "execution_error", "error": _describe(error)}
        output = captured.getvalue().rstrip("\n")
        try:
            json.dumps(value)
        except (TypeError, ValueError):
            value = repr(value)
        return {"type": "execution_result", "kind": "result", "value": value, "stdout": output}


def _describe(error: BaseException) -> str:
    text = str(error)
    if isinstance(error, SystemExit) and (not text or error.code is None):
        text = "code called exit()"
    return type(error).__name__ + ": " + text


def _jsonable(value):
    """Return ``value`` if JSON-encodable, otherwise a structure-preserving repr fallback."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        pass
    try:
        return json.loads(json.dumps(value, default=repr))
    except (TypeError, ValueError):
        return repr(value)


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #


def serve(transport: Transport) -> int:
    session = Session(transport)
    while True:
        try:
            request = transport.receive()
        except EOFError:
            return 0
        except BaseException as error:
            _safe_send(transport, {"type": "terminal_error", "error": _describe(error)})
            return 1
        try:
            kind = request.get("type")
            if kind == "shutdown":
                return 0
            if kind != "execute":
                raise ProtocolError(f"unknown host protocol message: {kind!r}")
            transport.send(session.execute(request))
        except EOFError:
            return 0
        except BaseException as error:
            _safe_send(transport, {"type": "terminal_error", "error": _describe(error)})
            return 1


def _safe_send(transport: Transport, message) -> None:
    try:
        transport.send(message)
    except Exception:
        pass


def main() -> int:
    transport = take_protocol_fds()
    try:
        policy = transport.receive()
    except EOFError:
        return 0
    except BaseException as error:
        _safe_send(transport, {"type": "terminal_error", "error": _describe(error)})
        return 2
    if policy.get("type") != "policy":
        _safe_send(transport, {"type": "terminal_error", "error": "ProtocolError: first message must be a policy"})
        return 2
    applied, skipped = apply_policy(policy)
    try:
        transport.send({"type": "ready", "applied": applied, "skipped": skipped, "pid": os.getpid()})
    except Exception:
        return 2
    return serve(transport)


if __name__ == "__main__":
    code = main()
    try:
        sys.stderr.flush()
    except Exception:
        pass
    os._exit(code)
