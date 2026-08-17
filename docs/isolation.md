# Isolation for the local subprocess interpreter

`LocalInterpreter(mode="subprocess")` runs generated code in a separate worker
process on the same machine. An `IsolationSpec` states what the caller
requires from that worker. The vocabulary is a set of portable *guarantees*,
not operating-system mechanisms. A backend either provides every requested
guarantee or refuses loudly. It never substitutes a weaker mechanism in
silence.

This document covers:

- the guarantee vocabulary;
- the public API (`IsolationSpec`, presets, `probe()`, `IsolationReport`);
- refusal and floor semantics;
- the mechanism each operating system uses for each guarantee;
- the worker protocol and what it does **not** protect against;
- the session directory layout;
- how to add paths when a runtime fails to start under the allowlist;
- what was tested live in this change.

Conformance (`check_interpreter` and friends) proves behavior through the
`CodeInterpreter` protocol. It does not prove isolation. Isolation is a backend
claim, surfaced through `probe()` before start and `IsolationReport` after
start. See [`abstraction-boundaries.md`](abstraction-boundaries.md).

## Purpose

The in-process `LocalInterpreter` gives generated code full authority over the
DSPy process. The subprocess mode moves that code into its own process and lets
the caller ask for confinement in a portable way:

```python
from dspy_interpreters import LocalInterpreter
from dspy_interpreters.isolation import IsolationSpec

interp = LocalInterpreter(mode="subprocess", isolation=IsolationSpec.confined())
try:
    interp.execute("import os; print(os.getcwd())")
    print(interp.isolation_report.to_dict())
finally:
    interp.shutdown()
```

If the machine cannot provide a requested guarantee, the constructor or
`start()` raises `IsolationUnsupportedError`. The interpreter never starts a
weaker worker and pretends the request was met.

## Guarantee vocabulary

These names are the constants in `dspy_interpreters.isolation.spec` and the
keys of `spec.GUARANTEES`. Reports and probes use the same names.

| Guarantee | Meaning |
|---|---|
| `own_address_space` | Generated code runs in a separate operating-system process, not in the DSPy process. |
| `filesystem_allowlist` | Only listed paths are readable or writable; everything else is denied. |
| `no_ambient_network` | The worker has no network stack access; host tools are the only external channel. |
| `memory_capped` | Worker memory is capped; exceeding the cap fails the allocation or kills the worker. |
| `cpu_time_capped` | Worker CPU time is capped; exceeding the cap kills the worker. |
| `process_count_capped` | The number of processes the worker can create is capped. |
| `wall_time_capped` | Each execute() call has a wall-clock deadline; exceeding it kills the worker. |
| `clean_environment` | Host environment variables are not inherited except an explicit passthrough list. |
| `private_tmp` | The worker sees a private temporary directory instead of the shared host one. |
| `killed_with_host` | The worker is killed when the host process dies. Guest-spawned processes die with it as long as they stay in the worker's process group or, in bwrap mode, its pid namespace; a guest that calls `setsid()` outside bwrap mode escapes (see the per-OS notes). |
| `no_new_privileges` | The worker cannot gain privileges through setuid/setgid or file capabilities. |
| `reduced_kernel_surface` | A syscall denylist blocks ptrace, mounts, modules, bpf, keyrings, and namespaces. |

## API

Everything below is exported from `dspy_interpreters.isolation`. The package
root (`dspy_interpreters`) also exports `IsolationSpec`, `IsolationReport`,
`IsolationUnsupportedError`, and `probe`.

### `IsolationSpec`

`IsolationSpec` is a frozen dataclass. Every non-default field is a *required*
guarantee. `spec.guarantees()` returns the derived set.

| Field | Type | Default | Guarantees it requests |
|---|---|---|---|
| `files` | `FilesystemPolicy \| None` | `None` | `filesystem_allowlist`; plus `private_tmp` when `files.private_tmp` is true |
| `network` | `NetworkPolicy` | `NetworkPolicy(mode="host")` | `no_ambient_network` when `mode="none"` |
| `limits` | `ResourceLimits` | all `None` | `memory_capped`, `cpu_time_capped`, `process_count_capped`, `wall_time_capped` for each non-`None` limit |
| `env` | `EnvPolicy` | `EnvPolicy(mode="inherit")` | `clean_environment` when `mode="clean"` |
| `require` | `frozenset[str]` | empty | the named guarantees, for example `{"no_new_privileges", "reduced_kernel_surface"}` |
| `backend_options` | `Mapping[str, Any]` | empty | none; tunes mechanisms only |

Every spec also requests `own_address_space` and `killed_with_host`.

The nested policies:

| Policy | Fields |
|---|---|
| `FilesystemPolicy` | `read: tuple[str, ...]`, `write: tuple[str, ...]`, `include_runtime: bool = True`, `private_tmp: bool = True`, `workdir: str \| None = None` |
| `NetworkPolicy` | `mode: "host" \| "none"` |
| `ResourceLimits` | `memory: int \| str \| None` (bytes or `"512M"`, `"2GiB"`), `cpu_seconds: float \| None`, `max_processes: int \| None`, `wall_time_seconds: float \| None` |
| `EnvPolicy` | `mode: "inherit" \| "clean"`, `passthrough: tuple[str, ...]`, `variables: Mapping[str, str]` |

`FilesystemPolicy.read` and `write` hold absolute paths (files or directories).
With `include_runtime`, the Python runtime (prefix, stdlib, site-packages) and
the operating-system library directories are readable. `workdir=None` means a
private per-session directory. With `EnvPolicy(mode="clean")`, only
`passthrough` names are copied from the host, `variables` are set explicitly,
and backends add what Python needs to start (`PATH`, `TMPDIR`, locale).

Invalid values raise `IsolationSpecError` (a `ValueError` and a
`CodeInterpreterError`) at construction. `spec.is_confined` is true when the
spec asks for anything beyond `own_address_space`, `killed_with_host`, and
`wall_time_capped`. `spec.describe()` returns the one-line summary that ends
the interpreter's `execution_instructions`.

### Presets

`IsolationSpec.trusted(*, wall_time_seconds=None)` is a plain worker process:
own address space, host filesystem, host network, inherited environment. It is
the same as `IsolationSpec()` plus an optional per-execute deadline.

`IsolationSpec.confined(...)` is the confined preset. Its keyword arguments and
defaults:

| Argument | Default |
|---|---|
| `read` | `()` |
| `write` | `()` |
| `workdir` | `None` (private per-session directory) |
| `network` | `"none"` |
| `memory` | `"1G"` |
| `cpu_seconds` | `120.0` |
| `max_processes` | `32` |
| `wall_time_seconds` | `120.0` |
| `env_passthrough` | `()` |
| `require` | `frozenset()` |
| `backend_options` | `None` |

It requests `filesystem_allowlist`, `private_tmp`, `no_ambient_network`,
`memory_capped`, `cpu_time_capped`, `process_count_capped`,
`wall_time_capped`, `clean_environment`, `own_address_space`, and
`killed_with_host`. Pass `require={"no_new_privileges",
"reduced_kernel_surface"}` to make those two mandatory as well; without them a
Linux backend still applies them when it can and reports them as extras.

### `backend_options`

`backend_options` never changes the requested guarantees. It selects or tunes
mechanisms:

| Key | Values | Effect |
|---|---|---|
| `"linux.launcher"` | `"auto"` (default), `"bwrap"`, `"native"` | `"bwrap"` requires Bubblewrap; `"native"` uses Landlock plus `unshare` from inside the worker; `"auto"` picks bwrap when it works, else native |
| `"darwin.profile_extra"` | SBPL text | Appended to the generated `sandbox-exec` profile, for example `(allow file-read* (subpath "/opt/data"))` |

### `probe()`

`probe(platform=sys.platform)` returns a `BackendCapabilities` for the native
backend of this machine. Call it to learn what a spec can ask for before you
build one:

```python
from dspy_interpreters.isolation import probe

caps = probe()
print(caps.name, caps.platform)
print(caps.supported)    # guarantee -> mechanism summary
print(caps.unsupported)  # guarantee -> concrete reason
print(caps.notes)
print(caps.to_dict())
```

The probe runs real checks once and caches them: for example, on Linux it
starts `bwrap` and `systemd-run` with a trivial command, queries the Landlock
ABI, and tries a user namespace in a child process. Unsupported reasons are
concrete, for example `bwrap not found on PATH; Landlock unavailable: Function
not implemented (kernel < 5.13 or CONFIG_SECURITY_LANDLOCK/lsm= not enabled?)`
or `... user namespaces disabled (apparmor_restrict_unprivileged_userns=1):
EPERM`.

`select_backend(spec, platform=sys.platform)` is the function the interpreter
uses. It returns the backend after checking it can meet `spec`, or raises
`IsolationUnsupportedError`. Unconfined specs (`spec.is_confined` is false)
always use the portable plain backend.

### `IsolationReport`

After a successful `start()`, `interp.isolation_report` holds an
`IsolationReport`:

| Attribute | Meaning |
|---|---|
| `backend` | Backend name |
| `platform` | `sys.platform` value the backend planned for |
| `requested` | `frozenset[str]` of guarantees the spec asked for |
| `guarantees` | `Mapping[str, str]`: every provided guarantee mapped to the mechanism used, for example `{"no_ambient_network": "bwrap --unshare-net"}` |
| `notes` | `tuple[str, ...]` of human-readable remarks, for example an optional mechanism the worker skipped |
| `extras` | Property: guarantees provided beyond the request |
| `missing` | Property: requested guarantees absent from `guarantees` (always empty for a running worker; `start()` refused otherwise) |
| `to_dict()` | JSON-friendly form |

### Refusal semantics

- The constructor calls `select_backend(spec)`. If a requested guarantee is
  not in the backend's `supported` table, it raises `IsolationUnsupportedError`
  with `unmet: {guarantee: reason}` and `backend: name`.
- `start()` sends the policy to the worker and waits for its `ready` message.
  Every name in the plan's `required_applied` list must appear in the worker's
  `applied` list. Otherwise the host kills the worker and raises
  `IsolationUnsupportedError({name: skipped-reason})`.
- `IsolationUnsupportedError` is a `CodeInterpreterError`, so callers that
  already handle interpreter failures see it.
- `mode="inprocess"` with an `isolation` argument raises
  `IsolationUnsupportedError`: the in-process mode cannot provide
  `own_address_space`.
- There is no silent downgrade. A backend never replaces a requested mechanism
  with a weaker one and continues.
- Optional items the worker skipped appear in `isolation_report.notes` as
  `optional policy item '<name>' not applied: <reason>`.
- Terminal failures include the tail of the worker's stderr (last 64 KiB) in
  the `CodeInterpreterError` message after `worker stderr:`.

### Floor semantics

A spec is a floor. A backend may apply more than the request and reports every
mechanism it applied. For example, the Linux backend always applies
`PR_SET_NO_NEW_PRIVS`, the seccomp denylist (on x86-64 and aarch64), and
`RLIMIT_CORE=0`, and in bwrap mode with a `files` policy it also applies
Landlock when the kernel has it, even when the spec did not require them.
Those show up in `report.extras`. Only *required* items can refuse the start;
an optional item that the worker skips becomes a note in `report.notes`.

### Interpreter properties

`LocalInterpreter(tools=None, output_fields=None, *, mode="inprocess",
isolation=None, python=None, startup_timeout=30.0)`:

- `mode`: `"inprocess"` (default, unchanged behavior) or `"subprocess"`.
- `isolation`: an `IsolationSpec`; `None` means `IsolationSpec()` in subprocess
  mode.
- `python`: interpreter executable for the worker; `None` means the host's
  `sys.executable`.
- `startup_timeout`: seconds to wait for the worker's `ready` message.
- Properties: `mode`, `isolation` (the spec, `None` in in-process mode),
  `isolation_report` (`IsolationReport | None`, set after `start()`),
  `execution_instructions`.
- An unknown `mode` raises `ValueError`.

The `execution_instructions` string ends with `spec.describe()`, so a model sees
the confinement it runs under, for example `filesystem limited to an
allowlist; no network access; limits: memory 1G, CPU 120s, processes 32, wall
time 120s per execution; clean environment`.

## Mechanisms per operating system

Backends live in `dspy_interpreters.isolation`: `_plain.py` (any OS, used
for unconfined specs), `_linux.py`, `_darwin.py`, `_windows.py`. `probe()`
returns the exact table for the current machine; the tables below list the
mechanisms each backend can use and the reasons it refuses.

Two guarantees are the same everywhere:

| Guarantee | Mechanism |
|---|---|
| `own_address_space` | Separate worker process spawned by the host |
| `wall_time_capped` | Host-side deadline per `execute()`; time spent inside host tools does not count; on expiry the host kills the process tree, marks the session ended, and raises `CodeInterpreterError` |

### Plain backend (any OS)

`select_backend()` uses the plain backend for every spec whose `is_confined`
is false (`IsolationSpec()`, `IsolationSpec.trusted()`), on every operating
system. It is also the native backend on platforms that are not Linux, macOS,
or Windows.

| Guarantee | Mechanism |
|---|---|
| `killed_with_host` | Linux: `PR_SET_PDEATHSIG`; other POSIX: ppid watchdog thread in the worker; Windows: job object `KILL_ON_JOB_CLOSE` when `kernel32` loads, else ppid watchdog. On POSIX these end the worker process itself; a helper the worker forks (`pgroup_reaper`) then SIGKILLs the worker's process group, so guest children die too unless they left the session with `setsid()` |
| `cpu_time_capped` | POSIX: `RLIMIT_CPU`; Windows: job object `PerProcessUserTimeLimit` |
| `process_count_capped` | POSIX: `RLIMIT_NPROC` (counts every process of the user); Windows: job object `ActiveProcessLimit` |
| `memory_capped` | Linux: `RLIMIT_AS`; Windows: job object `ProcessMemoryLimit`; macOS: unsupported (`RLIMIT_AS` not enforced); other platforms: unsupported (not verified) |
| `clean_environment` | Explicit environment plus `python -I` |
| `filesystem_allowlist`, `no_ambient_network`, `private_tmp`, `no_new_privileges`, `reduced_kernel_surface` | Not provided; the reason strings say to request them through the platform backend |

On Linux, macOS, and Windows a spec that asks for a cap or a clean environment
is confined, so `select_backend()` picks the native backend below instead of
the plain one. The plain rows for those guarantees matter only on other
platforms.

### Linux

The backend name is `linux`. The launcher is
`backend_options["linux.launcher"]`: `"bwrap"`, `"native"`, or `"auto"`
(default: bwrap when its probe works, else native). An unknown value raises
`IsolationSpecError`. `"bwrap"` on a machine without a working `bwrap` raises
`IsolationUnsupportedError({"linux.launcher": "bwrap requested: ..."})`.
Where two mechanisms are listed, the first is bwrap mode and the second is
native mode. The strings are the ones `probe()` and `IsolationReport` return.

| Guarantee | Mechanism |
|---|---|
| `filesystem_allowlist` | `bwrap bind-mount allowlist` (`--ro-bind-try` per read path, `--bind-try` per write path, empty root otherwise), reported as `bwrap bind-mount allowlist + Landlock ABI n` when the kernel also has Landlock / `Landlock ABI n + seccomp deny socket(AF_UNIX)`: Landlock applied inside the worker (`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`) plus a seccomp rule that answers `socket(AF_UNIX, ...)` with `EPERM`, because Landlock does not mediate `connect()` to a filesystem-path Unix socket of the host (`/var/run/docker.sock`, the D-Bus bus, X11) |
| `no_ambient_network` | `bwrap --unshare-net` / `unshare(CLONE_NEWUSER\|CLONE_NEWNET) + seccomp deny socket(AF_UNIX)` inside the worker (the network namespace removes IP and abstract Unix sockets; the seccomp rule removes filesystem-path Unix sockets) |
| `memory_capped` | `cgroup v2 memory.max via systemd-run --user --scope` (`MemoryMax=` plus `MemorySwapMax=0`) when the probe succeeds; else `RLIMIT_AS` |
| `cpu_time_capped` | `RLIMIT_CPU` (soft = hard = `cpu_seconds` + 1) |
| `process_count_capped` | `cgroup v2 pids.max via systemd-run --user --scope` (`TasksMax=`) when the probe succeeds; else `RLIMIT_NPROC` |
| `clean_environment` | `explicit environment + python -I` (the host passes exactly the worker variables; bwrap inherits them) |
| `private_tmp` | `TMPDIR set to the session tmp; bwrap mounts a private tmpfs at /tmp` / `TMPDIR set to the session tmp; host /tmp outside the Landlock allowlist` |
| `killed_with_host` | `bwrap --die-with-parent + PR_SET_PDEATHSIG` / `PR_SET_PDEATHSIG` (`SIGKILL`). bwrap mode tears down the whole pid namespace. Native mode ends the worker process; the worker's forked `pgroup_reaper` helper then SIGKILLs the worker's process group (guests that call `setsid()` escape it) |
| `no_new_privileges` | `PR_SET_NO_NEW_PRIVS`; always applied, required only when in `spec.require` |
| `reduced_kernel_surface` | `seccomp-bpf denylist (<machine>)` with `<machine>` = `x86_64` or `aarch64`; always applied where the architecture is supported, required when in `spec.require` and, in native mode, whenever a `files` policy or `network="none"` needs the `socket(AF_UNIX)` rule |

bwrap mode also uses `--unshare-user-try`, `--unshare-pid`, `--unshare-ipc`,
`--unshare-uts`, `--unshare-cgroup-try`, `--die-with-parent`,
`--new-session`, `--proc /proc`, `--dev /dev`, `--tmpfs /tmp` (with
`private_tmp`), `--remount-ro /`, and `--chdir` into the work directory. The
sandbox root is an empty tmpfs; only the bound paths exist inside it.
Top-level symlinks such as `/lib -> usr/lib` are recreated with `--symlink`.
When the spec has no `files` policy (for example only `network="none"`),
bwrap binds the host `/` read-write. In bwrap mode with a `files` policy, the
worker also applies Landlock as an optional extra when the kernel has it. In
native mode Landlock and `unshare` are *required*, and so is the seccomp
filter with its `socket(AF_UNIX)` rule whenever a `files` policy or
`network="none"` is requested: the host refuses at `start()` if the worker
reports any of them as skipped, and `probe()` / `plan()` refuse
`filesystem_allowlist` and `no_ambient_network` in native mode on machines
whose architecture the seccomp denylist does not support (`filesystem-path
Unix sockets cannot be blocked without the seccomp denylist ...`). Inside a
native worker `socket.socket(socket.AF_UNIX)` raises `PermissionError`;
`socket.socketpair()`, `asyncio`, `subprocess`, and `multiprocessing` pipes
keep working. In bwrap mode the rule is not applied: the sandbox root has no
host sockets, but a Unix socket that lives inside a *listed* read path stays
connectable (a read-only bind mount does not block `connect()`).

Native mode also forks a small helper (`pgroup_reaper`) after the ratchet.
It polls its parent every 0.5 s and, when the worker is gone, calls
`killpg(0, SIGKILL)` on the worker's process group (created by
`start_new_session=True`), so guest processes do not outlive an abrupt host
death. The helper is optional (a note reports it when it could not be forked),
it counts as one process against `max_processes`, it does not catch guests
that call `setsid()`, and it is a child of the worker: guest code that calls
`os.wait()` without children of its own blocks instead of raising
`ChildProcessError`.

The bwrap probe runs `bwrap --unshare-all --die-with-parent --ro-bind / /
--dev /dev --proc /proc -- python -I -c pass` once. The cgroup probe runs
`systemd-run --user --scope --quiet --collect -p MemoryMax=... -p TasksMax=...
-- ...` once. Probes are cached for the process; `clear_probe_cache()` in
`dspy_interpreters.isolation._linux` forces a re-probe.

The seccomp denylist answers these syscalls with `EPERM`: `ptrace`, `mount`,
`umount2`, `pivot_root`, `swapon`, `swapoff`, `reboot`, `kexec_load`,
`kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `keyctl`,
`add_key`, `request_key`, `bpf`, `perf_event_open`, `userfaultfd`, `unshare`,
`setns`, `personality`, `process_vm_readv`, `process_vm_writev`,
`open_by_handle_at`, `acct`, `settimeofday`, `clock_settime`, `adjtimex`,
`quotactl`, `chroot`, `mknod`, `mknodat`, `io_uring_setup`, `io_uring_enter`,
`io_uring_register`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`,
`fsmount`, `fspick`, `pidfd_getfd`, `mount_setattr`, `kcmp`, `ioperm`,
`iopl`, `vhangup`. `clone3` returns `ENOSYS` so glibc falls back to `clone`,
and `clone` with `CLONE_NEWUSER` returns `EPERM`. A syscall from a different
architecture, or an x32 syscall on x86-64, kills the process. Only x86-64 and
aarch64 are supported; on other machines the worker reports the seccomp step
as skipped with `"unsupported architecture"`.

Reasons a Linux probe reports `unsupported` (the exact strings come from
`probe()`; `<bwrap>` is the bwrap probe detail such as `bwrap not found on
PATH` or `bwrap probe exited with status 1: ...`):

| Guarantee | Reason |
|---|---|
| `filesystem_allowlist`, `private_tmp` | `<bwrap>; Landlock unavailable: <errno text> (kernel < 5.13 or CONFIG_SECURITY_LANDLOCK/lsm= not enabled?)` |
| `no_ambient_network` | `<bwrap>; user namespaces disabled (apparmor_restrict_unprivileged_userns=1, kernel.unprivileged_userns_clone=0, user.max_user_namespaces=0 as applicable): <errno text>` |
| `reduced_kernel_surface` | `seccomp denylist supports x86_64 and aarch64 only, not '<machine>'` |

`memory_capped`, `cpu_time_capped`, `process_count_capped`,
`clean_environment`, `killed_with_host`, and `no_new_privileges` are always
supported on Linux.

### macOS

The macOS backend runs the worker under `sandbox-exec -p <profile>`. The
Seatbelt profile language is not documented by Apple and can change between
releases; the backend marks it **experimental** in its notes.

| Guarantee | Mechanism or reason |
|---|---|
| `filesystem_allowlist` | `sandbox-exec` SBPL profile (deny default, allowlisted paths): `(deny default)`, `(allow file-read* ...)` per read path, `(allow file-read* file-write* ...)` per write path (SBPL `file-write*` does not include `file-read*`, so write paths are read-write as on Linux); experimental |
| `no_ambient_network` | `sandbox-exec (deny network*)` |
| `memory_capped` | unsupported: `macOS does not enforce RLIMIT_AS; no cgroup equivalent` |
| `cpu_time_capped` | `RLIMIT_CPU` |
| `process_count_capped` | `RLIMIT_NPROC (per-user process count)`; every process of the current user counts, not only the worker's descendants |
| `clean_environment` | `explicit environment + python -I` |
| `private_tmp` | private `TMPDIR` under the session directory, allowlisted in the profile |
| `killed_with_host` | worker ppid watchdog (a thread polls `os.getppid()` every 0.5 s); macOS has no `PR_SET_PDEATHSIG`. The watchdog runs inside the worker (best effort against hostile guest code that rebinds `os` functions or holds the GIL); the `pgroup_reaper` helper then SIGKILLs the worker's process group |
| `no_new_privileges` | unsupported: `macOS has no PR_SET_NO_NEW_PRIVS equivalent; not implemented` |
| `reduced_kernel_surface` | unsupported: `macOS has no seccomp equivalent; not implemented` |

When `sandbox-exec` is missing or its probe fails, `filesystem_allowlist`,
`no_ambient_network`, and `private_tmp` are unsupported with the probe failure
as the reason (for example `sandbox-exec not found`). The backend name is
`darwin-sandbox-exec`.

Use `backend_options={"darwin.profile_extra": "..."}` to append SBPL rules to
the generated profile.

`IsolationSpec.confined()` defaults to `memory="1G"`, which macOS refuses
(`memory_capped` is unsupported). On macOS pass
`IsolationSpec.confined(memory=None)`.

The read allowlist deliberately does not contain `/var` or `/private/var`:
`$TMPDIR` lives under `/private/var/folders`, which holds the host's temporary
files and every other session's `work/` and `tmp/` directories. Only
`/private/var/db/dyld`, `/private/var/db/timezone`, `/private/var/select`, and
`/private/var/run` are readable. The session directories are readable through
their own write rule. With `network="host"` the profile also allows
`mach-lookup` of `com.apple.dnssd.service` (name resolution) and, always,
`ipc-posix-sem` next to `ipc-posix-shm`. Without a `files` policy
(network-only confinement) `process-exec` follows the read paths, i.e. `/`.

### Windows

The Windows backend uses a Job Object created through `kernel32` (`ctypes`).

| Guarantee | Mechanism or reason |
|---|---|
| `filesystem_allowlist` | unsupported: `requires AppContainer/ACL confinement; not implemented` |
| `no_ambient_network` | unsupported: `requires AppContainer network capability model; not implemented` |
| `memory_capped` | `job object ProcessMemoryLimit` (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`) |
| `cpu_time_capped` | `job object PerProcessUserTimeLimit` (`JOB_OBJECT_LIMIT_PROCESS_TIME`, 100 ns units) |
| `process_count_capped` | `job object ActiveProcessLimit` (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS`); the count includes the worker itself |
| `clean_environment` | `explicit environment + python -I` |
| `private_tmp` | Listed as `TEMP/TMP point to a private session directory`, but a spec requests it only together with a `files` policy, which this backend refuses; so it is not reachable in practice |
| `killed_with_host` | `job object KILL_ON_JOB_CLOSE`; the job handle closes when the host process exits |
| `no_new_privileges` | unsupported: `no Windows equivalent of PR_SET_NO_NEW_PRIVS; not implemented` |
| `reduced_kernel_surface` | unsupported: `no seccomp equivalent on Windows; not implemented` |

When `kernel32` cannot be loaded, the four job-object guarantees are
unsupported with the reason `Windows job objects unavailable: ...`. The backend
name is `windows-job-object`.

The Job Object also sets `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION` and the
basic UI restrictions. The worker is started with
`CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW`. `IsolationSpec.confined()`
therefore refuses on Windows; use `IsolationSpec(limits=ResourceLimits(...),
env=EnvPolicy(mode="clean"))` for the caps that Windows can enforce.

## Worker protocol

The host writes the worker source (`dspy_interpreters/isolation/_worker.py`)
into the session `bootstrap/` directory and starts it as
`python [-I] -u bootstrap/worker.py` (wrapped by `bwrap`, `systemd-run`, or
`sandbox-exec` when the backend uses them). Messages are line-delimited JSON
(UTF-8, `separators=(",", ":")`) over the worker's inherited stdin and stdout.

Startup:

1. The worker moves fd 0 and fd 1 to private high descriptors, points fd 0 at
   `/dev/null`, and duplicates fd 2 onto fd 1. Stray writes to fd 1 by guest
   code land on stderr, not on the protocol pipe.
2. The host sends `{"type": "policy", "version": 1, "die_with_parent": true,
   "pgroup_reaper": bool, "chdir": ..., "rlimits": {...},
   "landlock": {...} | null, "unshare_net": {...} | null,
   "no_new_privs": {...} | null,
   "seccomp": {"required": bool, "deny_unix_sockets": bool} | null}` as the
   first line. `pgroup_reaper` is true only when the backend started the
   worker in a session of its own (`start_new_session=True`).
3. The worker applies the policy in a fixed order (umask `0o077`, chdir,
   rlimits, `PR_SET_PDEATHSIG`, Landlock, `unshare`, `PR_SET_NO_NEW_PRIVS`,
   seccomp, then the forked `pgroup_reaper` helper) before it starts any
   thread. It never crashes on a failed step. It answers `{"type": "ready",
   "applied": [...], "skipped": {name: reason}, "pid": int}`. `applied` names
   are `umask`, `chdir`, `rlimit:<name>`, `pdeathsig`, `landlock:abi<N>`,
   `unshare_net`, `no_new_privs`, `seccomp:<machine>`, `pgroup_reaper`,
   `ppid_watchdog`.
4. The host checks `applied` against the plan's `required_applied` list
   (exact name or `name:` prefix, so `"landlock"` matches `"landlock:abi4"`).
   Skipped optional items become `IsolationReport.notes`.

Serving: `{"type": "execute", "code", "variables", "tools": [names],
"output_fields"}` produces `tool_request` / `tool_response` round trips (host
tools run in the host process; the guest blocks) and one `execution_result`
with `kind` in `final`, `syntax`, `execution_error`, `result`. `SystemExit`
and every other `BaseException` raised by guest code (`KeyboardInterrupt`,
`GeneratorExit`, ...) is an `execution_error`; the session survives.
`{"type": "shutdown"}` ends the worker. Any protocol violation is a
`terminal_error` and ends the session. The host reads stdout on a daemon
thread with a queue and drains stderr into a bounded ring buffer that appears
in terminal error messages; each reader thread owns and closes its stream, so
`shutdown()` and the wall-time kill never block on a pipe that an escaped
guest process still holds open. The host validates tool names and output
field names before it sends an `execute` request (a bad name raises a
recoverable `CodeInterpreterError`; the worker's own check is defence in
depth). If a `BaseException` leaves `execute()` while a request is in flight
(a `KeyboardInterrupt` while waiting, a host tool that raises one), the host
kills the worker and marks the session ended instead of leaving the protocol
one reply behind. A process forked by guest code (`os.fork()` without
`exec`) that reaches the protocol exits immediately instead of answering in
the worker's place.

### What the protocol does not protect against

- **Frame forgery from inside the worker.** The protocol descriptors are
  private high fds, not fd 0/1, so casual `print` cannot corrupt them. But
  guest code runs in the same process as the worker loop. It can find the fds
  (`/proc/self/fd`, `os.listdir`, brute force) and write forged
  `tool_request` frames or replay an authorized tool call. Host tools are
  authorized against the current host-side tool map, so the guest cannot call
  an unbound tool, but a bound non-idempotent tool can be replayed. A real
  intra-worker boundary needs a separate broker process.
- **Kernel exploits.** Every mechanism here is enforced by the same kernel the
  guest talks to. A kernel privilege escalation escapes bwrap, Landlock,
  seccomp, Seatbelt, and Job Objects alike.
- **Hostile multi-tenancy.** These backends reduce the blast radius of
  model-generated code on one user's machine. They do not make it safe to run
  mutually hostile tenants side by side. Use a microVM or gVisor for that.
- **GPU and other devices.** Device access is not addressed. bwrap mode mounts a
  minimal `/dev`; native mode allows only the listed device files.
- **Side channels, timing, and covert channels** through shared caches or the
  filesystem metadata that stays readable.
- **The host tools themselves.** A tool that reads secrets or runs commands
  gives the guest that power regardless of the sandbox.
- **Guest processes that leave the session.** Outside bwrap mode, `kill()`,
  the wall-time kill, and the `pgroup_reaper` helper SIGKILL the worker's
  process group. A guest process that called `setsid()`
  (`subprocess.Popen(..., start_new_session=True)`, daemonizers) survives them
  and can outlive the host; one pipe descriptor stays open until it exits.
  bwrap mode tears down the whole pid namespace; a `systemd-run` scope on
  Linux is killed as a whole too.
- **Unix sockets inside listed paths (bwrap mode).** The native launcher
  denies `socket(AF_UNIX)`; bwrap mode does not, so a host Unix socket that
  lives inside a listed read path stays connectable there.

## Session directory layout

`start()` creates `tempfile.mkdtemp(prefix="dspy-interp-")` and the
sub-directories from `session_paths()`:

| Path | Purpose | Mode |
|---|---|---|
| `bootstrap/` | `worker.py`, written before start; directory set to `0o500` after writing | read-only for the worker |
| `work/` | worker current directory (`FilesystemPolicy.workdir=None`), also `HOME` in clean environments | read-write |
| `tmp/` | `TMPDIR` for the worker; in bwrap mode with `private_tmp`, `/tmp` itself is a separate empty tmpfs | read-write |

On macOS the session directory lives under the host `$TMPDIR`
(`/private/var/folders/...`); other confined sessions cannot read it because
`/var` is not in the read allowlist.

`shutdown()` removes the whole session directory and ignores errors. A
wall-time kill or a terminal protocol error also kills the worker and removes
the directory. Still call `shutdown()` in a `finally` block; it is idempotent.

## Adding paths when a runtime fails to start

Under `filesystem_allowlist` the worker sees only:

- the Python runtime paths from `runtime_read_paths(python)`: the executable,
  `sys.prefix`, `sys.base_prefix`, the stdlib, `site-packages`, and every entry
  of `sys.path`;
- the operating-system paths from `system_read_paths()` (for Linux: `/usr`,
  `/lib*`, `/bin`, `/sbin`, `/opt`, `/nix/store`, `/etc/ld.so.*`,
  `/etc/ssl`, `/etc/passwd`, `/etc/hosts`, `/etc/resolv.conf`, and a few
  more; for macOS: `/usr/lib`, `/usr/bin`, `/usr/local`, `/System`,
  `/Library/Frameworks`, `/opt/homebrew`, `/private/etc`,
  `/private/var/db/dyld`, `/private/var/select`, `/private/var/run`, and the
  device files, never `/var` as a whole);
- `FilesystemPolicy.read` and `write`, plus the session directories.

With `FilesystemPolicy(include_runtime=False)` only the session directories
and the listed paths remain; use it only with a `python` that lives inside a
listed path.

If the worker fails to start (`IsolationUnsupportedError` at `start()`, a
`CodeInterpreterError` with a stderr excerpt, or an `ImportError` on the first
`execute`), the runtime probably needs a path outside that list. Typical
cases: a virtual environment whose `python` is a symlink into a prefix outside
`sys.prefix` (both ends of the symlink are added, but not a third location),
shared libraries in an unusual directory, a package that reads data files from
`$HOME`, or a `.pth` file that adds a directory that does not exist yet.

To fix it:

1. Read the stderr excerpt in the error message; the failing `open()` names the
   path.
2. Add the directory to the spec: `IsolationSpec.confined(read=("/path",))`
   or `write=("/path",)` for directories the code must modify.
3. In bwrap mode you can also test by hand: `bwrap --ro-bind /path /path ...`.
   On macOS, add SBPL rules through `backend_options["darwin.profile_extra"]`
   when the generic read/write rules are not enough (for example
   `mach-lookup` services).
4. Re-run `probe()` if the failure is a refusal at construction; the reason
   string names the missing mechanism, not a missing path.

Missing paths in the allowlist are skipped silently (both `bwrap --*-bind-try`
and the Landlock rule builder ignore paths that do not exist), so listing a
path that may appear later is safe.

## Testing status

- **Linux** is the only operating system tested live in this change
  (x86-64). `tests/test_local_subprocess.py` runs the plain backend through
  `check_interpreter`, `check_bind`, `check_execution_instructions`,
  `check_rlm`, and `check_flex_facade`. `tests/test_isolation_linux.py` runs
  the confined preset under both launchers (`bwrap` and `native`) through
  `check_interpreter` and checks network denial (TCP, filesystem-path and
  abstract Unix sockets), allowlist denial, `NoNewPrivs`, seccomp (`unshare`,
  `personality`, `socket(AF_UNIX)`), memory, CPU, and process caps, clean
  environment, private tmp, and kill-with-host including a guest-spawned
  child. `tests/test_local_subprocess.py` also covers escaped grandchildren
  holding the pipes, interrupted executions, guests that close their stdio,
  and invalid output fields. `tests/test_worker.py` covers the worker
  protocol, ratchet, the AF_UNIX seccomp rule, and the process-group reaper.
  Tests that need a mechanism the machine lacks skip with the probe reason.
- **macOS** and **Windows** backends were unit-tested for plan generation only
  (Seatbelt profile text, Job Object flags and structure sizes) from a Linux
  machine. Their live tests are skipped off-platform and have not run in this
  change. Treat the macOS profile as experimental and the Windows resource caps
  as untested until a live run confirms them.
- Conformance passing in `mode="subprocess"` proves protocol behavior, not
  isolation. Only the isolation tests and `IsolationReport` speak to isolation.
