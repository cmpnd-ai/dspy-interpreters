"""Linux backend: pure planning tests (any OS) and live confinement tests (Linux only)."""

from __future__ import annotations

import contextlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid

import pytest
from dspy import CodeExecutionError, CodeInterpreterError

from dspy_interpreters import LocalInterpreter, check_interpreter
from dspy_interpreters.isolation import (
    CLEAN_ENVIRONMENT,
    CPU_TIME_CAPPED,
    FILESYSTEM_ALLOWLIST,
    KILLED_WITH_HOST,
    MEMORY_CAPPED,
    NO_AMBIENT_NETWORK,
    NO_NEW_PRIVILEGES,
    PRIVATE_TMP,
    PROCESS_COUNT_CAPPED,
    REDUCED_KERNEL_SURFACE,
    FilesystemPolicy,
    IsolationSpec,
    IsolationSpecError,
    IsolationUnsupportedError,
    NetworkPolicy,
    ResourceLimits,
    _linux,
)
from dspy_interpreters.isolation._backend import session_paths
from dspy_interpreters.isolation._linux import (
    DEVICE_RW_FILES,
    LAUNCHER_OPTION,
    LinuxBackend,
    ProbeResult,
    build_bwrap_argv,
    build_policy,
    build_systemd_run_prefix,
    launcher_of,
    resolve_top_level_symlinks,
)

IS_LINUX = sys.platform.startswith("linux")
LAUNCHERS = ("bwrap", "native")

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _session(tmp_path) -> tuple[str, str]:
    session_dir = tmp_path / "session"
    paths = session_paths(str(session_dir))
    for path in paths.values():
        os.makedirs(path, exist_ok=True)
    worker = os.path.join(paths["bootstrap"], "worker.py")
    with open(worker, "w") as handle:
        handle.write("# worker\n")
    return str(session_dir), worker


def _fake_probes(monkeypatch, *, bwrap=True, landlock=4, userns=True, systemd=True, machine="x86_64") -> None:
    monkeypatch.setattr(
        _linux,
        "probe_bwrap",
        lambda: ProbeResult(bwrap, "bwrap works" if bwrap else "bwrap not found on PATH", value="/usr/bin/bwrap"),
    )
    monkeypatch.setattr(
        _linux,
        "probe_landlock_abi",
        lambda: ProbeResult(
            bool(landlock),
            f"Landlock ABI {landlock}" if landlock else "Landlock unavailable: Function not implemented",
            value=landlock,
        ),
    )
    monkeypatch.setattr(
        _linux,
        "probe_userns",
        lambda: ProbeResult(
            userns,
            "unprivileged user namespaces work"
            if userns
            else "user namespaces disabled (apparmor_restrict_unprivileged_userns=1): EPERM",
        ),
    )
    monkeypatch.setattr(
        _linux,
        "probe_systemd_run",
        lambda: ProbeResult(
            systemd, "systemd-run works" if systemd else "systemd-run not found on PATH", value="/usr/bin/systemd-run"
        ),
    )
    monkeypatch.setattr(_linux, "seccomp_machine", lambda: machine)


def _plan(spec, tmp_path):
    session_dir, worker = _session(tmp_path)
    return LinuxBackend().plan(spec, python=sys.executable, worker_path=worker, session_dir=session_dir)


def _index_of(argv, option, value):
    for index in range(len(argv) - 1):
        if argv[index] == option and argv[index + 1] == value:
            return index
    raise AssertionError(f"{option} {value} not in {argv}")


# --------------------------------------------------------------------------- #
# Pure planning tests (run on every OS)
# --------------------------------------------------------------------------- #


def test_bwrap_argv_allowlist_shape(tmp_path):
    ro = tmp_path / "ro"
    work = tmp_path / "work"
    session_tmp = tmp_path / "tmp"
    for path in (ro, work, session_tmp):
        path.mkdir()
    command = [sys.executable, "-I", "-u", "/x/worker.py"]
    argv = build_bwrap_argv(
        bwrap="/usr/bin/bwrap",
        command=command,
        workdir=str(work),
        read_paths=[str(ro)],
        write_paths=[str(work), str(session_tmp)],
        private_tmp=True,
        network_none=True,
        unsetenv=["XDG_RUNTIME_DIR"],
    )
    assert argv[0] == "/usr/bin/bwrap"
    for flag in ("--unshare-user-try", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net"):
        assert flag in argv
    assert "--die-with-parent" in argv and "--new-session" in argv
    proc_at = _index_of(argv, "--proc", "/proc")
    _index_of(argv, "--dev", "/dev")
    tmpfs_at = _index_of(argv, "--tmpfs", "/tmp")
    ro_at = _index_of(argv, "--ro-bind-try", str(ro))
    assert argv[ro_at + 2] == str(ro)
    work_at = _index_of(argv, "--bind-try", str(work))
    _index_of(argv, "--bind-try", str(session_tmp))
    # Binds under /tmp must come after the tmpfs mount; others before the special mounts.
    for at, path in ((ro_at, str(ro)), (work_at, str(work))):
        if path.startswith("/tmp/"):
            assert at > tmpfs_at
        else:
            assert at < proc_at
    assert _index_of(argv, "--remount-ro", "/") > work_at
    assert _index_of(argv, "--chdir", str(work)) > 0
    _index_of(argv, "--unsetenv", "XDG_RUNTIME_DIR")
    assert argv[-len(command) - 1] == "--"
    assert argv[-len(command) :] == command
    assert "--clearenv" not in argv  # the launcher environment already is the worker environment


def test_bwrap_argv_host_network_and_no_private_tmp(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    argv = build_bwrap_argv(
        bwrap="bwrap", command=["python"], workdir=str(work), write_paths=[str(work)], private_tmp=False
    )
    assert "--unshare-net" not in argv
    assert "--tmpfs" not in argv
    assert "--remount-ro" in argv


def test_bwrap_argv_host_filesystem(tmp_path):
    argv = build_bwrap_argv(bwrap="bwrap", command=["python"], workdir=str(tmp_path), host_filesystem=True)
    assert argv[_index_of(argv, "--bind", "/") + 2] == "/"
    assert "--remount-ro" not in argv
    assert "--ro-bind-try" not in argv
    _index_of(argv, "--proc", "/proc")


def test_bwrap_argv_root_writable_skips_remount(tmp_path):
    argv = build_bwrap_argv(bwrap="bwrap", command=["python"], workdir=str(tmp_path), write_paths=["/"])
    assert "--remount-ro" not in argv


def test_top_level_symlink_resolution(monkeypatch):
    monkeypatch.setattr(os.path, "islink", lambda path: path == "/lib")
    monkeypatch.setattr(os, "readlink", lambda path: "usr/lib")
    monkeypatch.setattr(os.path, "realpath", lambda path: "/usr/lib" if path == "/lib" else path)
    paths, symlinks = resolve_top_level_symlinks(["/lib/x86_64-linux-gnu", "/usr/bin", "/lib"])
    assert paths == ["/usr/lib/x86_64-linux-gnu", "/usr/bin", "/usr/lib"]
    assert symlinks == [("usr/lib", "/lib")]


@pytest.mark.skipif(not (IS_LINUX and os.path.islink("/lib")), reason="needs a merged-/usr Linux (/lib symlink)")
def test_bwrap_argv_recreates_lib_symlink(tmp_path):
    argv = build_bwrap_argv(bwrap="bwrap", command=["python"], workdir=str(tmp_path), read_paths=["/lib", "/usr"])
    at = _index_of(argv, "--symlink", os.readlink("/lib"))
    assert argv[at + 2] == "/lib"
    assert "/lib" not in [argv[i + 1] for i, item in enumerate(argv) if item == "--ro-bind-try"]


def test_systemd_run_prefix():
    prefix = build_systemd_run_prefix(
        systemd_run="/usr/bin/systemd-run", unit="dspy-interp-abc.scope", memory_bytes=1024, max_processes=7
    )
    assert prefix[:4] == ["/usr/bin/systemd-run", "--user", "--scope", "--quiet"]
    assert "--collect" in prefix and "--unit=dspy-interp-abc.scope" in prefix
    assert "MemoryMax=1024" in prefix and "MemorySwapMax=0" in prefix and "TasksMax=7" in prefix
    assert prefix[-1] == "--"
    only_memory = build_systemd_run_prefix(systemd_run="s", unit="u", memory_bytes=5, max_processes=None)
    assert not any(item.startswith("TasksMax") for item in only_memory)


def test_launcher_option_validation():
    assert launcher_of(IsolationSpec()) == "auto"
    assert launcher_of(IsolationSpec(backend_options={LAUNCHER_OPTION: "native"})) == "native"
    with pytest.raises(IsolationSpecError):
        launcher_of(IsolationSpec(backend_options={LAUNCHER_OPTION: "docker"}))


def test_build_policy_native():
    spec = IsolationSpec.confined(require={NO_NEW_PRIVILEGES, REDUCED_KERNEL_SURFACE})
    policy, required = build_policy(
        spec, launcher="native", work_dir="/w", read_paths=["/usr", "/w"], write_paths=["/w"], use_cgroup=False
    )
    assert policy["version"] == 1 and policy["die_with_parent"] is True and policy["chdir"] == "/w"
    assert policy["rlimits"] == {"core": 0, "cpu": 121, "as": 1024**3, "nproc": 32}
    assert policy["landlock"] == {
        "required": True,
        "read": ["/usr", "/w"],
        "write": ["/w"],
        "rw_files": list(DEVICE_RW_FILES),
    }
    assert policy["unshare_net"] == {"required": True}
    assert policy["no_new_privs"] == {"required": True}
    assert policy["seccomp"] == {"required": True, "deny_unix_sockets": True}
    assert policy["pgroup_reaper"] is True
    assert set(required) == {
        "pdeathsig",
        "rlimit:cpu",
        "rlimit:as",
        "rlimit:nproc",
        "landlock",
        "unshare_net",
        "no_new_privs",
        "seccomp",
    }
    assert set(policy) == {
        "version",
        "die_with_parent",
        "pgroup_reaper",
        "chdir",
        "rlimits",
        "landlock",
        "unshare_net",
        "no_new_privs",
        "seccomp",
    }


def test_build_policy_bwrap_with_cgroup():
    spec = IsolationSpec.confined()
    policy, required = build_policy(
        spec, launcher="bwrap", work_dir="/w", read_paths=["/usr"], write_paths=["/w"], use_cgroup=True
    )
    assert "as" not in policy["rlimits"] and "nproc" not in policy["rlimits"]
    assert policy["landlock"]["required"] is False
    assert policy["unshare_net"] is None
    assert policy["no_new_privs"] == {"required": False}
    assert policy["seccomp"] == {"required": False, "deny_unix_sockets": False}
    assert policy["pgroup_reaper"] is False  # bwrap tears down its pid namespace
    assert set(required) == {"pdeathsig", "rlimit:cpu"}


def test_build_policy_native_requires_seccomp_for_unix_sockets():
    # Without REDUCED_KERNEL_SURFACE in spec.require the AF_UNIX rule still makes seccomp required in native mode.
    for spec in (IsolationSpec.confined(), IsolationSpec(network=NetworkPolicy(mode="none"))):
        policy, required = build_policy(
            spec, launcher="native", work_dir="/w", read_paths=[], write_paths=[], use_cgroup=True
        )
        assert policy["seccomp"] == {"required": True, "deny_unix_sockets": True}
        assert "seccomp" in required
    # bwrap mode: optional, no AF_UNIX rule.  Native mode without files or network policy: optional as well.
    policy, required = build_policy(
        IsolationSpec.confined(), launcher="bwrap", work_dir="/w", read_paths=[], write_paths=[], use_cgroup=True
    )
    assert policy["seccomp"] == {"required": False, "deny_unix_sockets": False} and "seccomp" not in required
    policy, required = build_policy(
        IsolationSpec.trusted(), launcher="native", work_dir="/w", read_paths=[], write_paths=[], use_cgroup=True
    )
    assert policy["seccomp"] == {"required": False, "deny_unix_sockets": False} and "seccomp" not in required
    # Native mode on a machine without the seccomp denylist: the policy is still sent because it is required.
    policy, required = build_policy(
        IsolationSpec.confined(),
        launcher="native",
        work_dir="/w",
        read_paths=[],
        write_paths=[],
        use_cgroup=True,
        seccomp_supported=False,
    )
    assert policy["seccomp"]["required"] is True and "seccomp" in required


def test_build_policy_without_seccomp_support_or_files():
    spec = IsolationSpec(network=NetworkPolicy(mode="none"))
    policy, required = build_policy(
        spec, launcher="bwrap", work_dir="/w", read_paths=[], write_paths=[], use_cgroup=False, seccomp_supported=False
    )
    assert policy["landlock"] is None and policy["seccomp"] is None
    assert required == ("pdeathsig",)
    with pytest.raises(ValueError):
        build_policy(spec, launcher="docker", work_dir="/w", read_paths=[], write_paths=[], use_cgroup=False)


def test_plan_bwrap_with_cgroup(tmp_path, monkeypatch):
    _fake_probes(monkeypatch)
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.setenv("HOST_SECRET", "hidden")
    spec = IsolationSpec.confined(backend_options={LAUNCHER_OPTION: "bwrap"})
    plan = _plan(spec, tmp_path)
    session = session_paths(str(tmp_path / "session"))
    assert plan.argv[0] == "/usr/bin/systemd-run"
    assert "MemoryMax=1073741824" in plan.argv and "TasksMax=32" in plan.argv
    bwrap_at = plan.argv.index("/usr/bin/bwrap")
    assert plan.argv[bwrap_at - 1] == "--"
    assert "--unshare-net" in plan.argv and "--die-with-parent" in plan.argv
    assert plan.argv[-3:] == ["-I", "-u", os.path.join(session["bootstrap"], "worker.py")]
    _index_of(plan.argv, "--ro-bind-try", session["bootstrap"])
    _index_of(plan.argv, "--bind-try", session["work"])
    _index_of(plan.argv, "--bind-try", session["tmp"])
    _index_of(plan.argv, "--tmpfs", "/tmp")
    _index_of(plan.argv, "--chdir", session["work"])
    _index_of(plan.argv, "--unsetenv", "XDG_RUNTIME_DIR")
    _index_of(plan.argv, "--unsetenv", "INVOCATION_ID")
    assert plan.cwd == session["work"]
    assert plan.env["XDG_RUNTIME_DIR"] == "/run/user/1000"
    assert plan.env["TMPDIR"] == session["tmp"] and plan.env["HOME"] == session["work"]
    assert "HOST_SECRET" not in plan.env
    assert plan.popen_kwargs == {"start_new_session": True}
    assert plan.policy["landlock"]["required"] is False
    assert "/" in plan.policy["landlock"]["read"] and session["bootstrap"] in plan.policy["landlock"]["read"]
    assert plan.policy["unshare_net"] is None
    assert "as" not in plan.policy["rlimits"]
    assert set(plan.required_applied) == {"pdeathsig", "rlimit:cpu"}
    assert plan.state["launcher"] == "bwrap" and plan.state["systemd_unit"].endswith(".scope")
    report = plan.report
    assert report.backend == "linux" and report.missing == frozenset()
    assert report.guarantees[FILESYSTEM_ALLOWLIST] == "bwrap bind-mount allowlist + Landlock ABI 4"
    assert report.guarantees[NO_AMBIENT_NETWORK] == "bwrap --unshare-net"
    assert report.guarantees[MEMORY_CAPPED] == "cgroup v2 memory.max via systemd-run --user --scope"
    assert report.guarantees[PROCESS_COUNT_CAPPED] == "cgroup v2 pids.max via systemd-run --user --scope"
    assert report.guarantees[CPU_TIME_CAPPED] == "RLIMIT_CPU"
    assert report.guarantees[KILLED_WITH_HOST] == "bwrap --die-with-parent + PR_SET_PDEATHSIG"
    assert report.guarantees[CLEAN_ENVIRONMENT] == "explicit environment + python -I"
    assert "tmpfs" in report.guarantees[PRIVATE_TMP]
    assert report.guarantees[NO_NEW_PRIVILEGES] == "PR_SET_NO_NEW_PRIVS"
    assert report.guarantees[REDUCED_KERNEL_SURFACE] == "seccomp-bpf denylist (x86_64)"
    assert any(note.startswith("launcher: bwrap") for note in report.notes)


def test_plan_native_with_cgroup(tmp_path, monkeypatch):
    _fake_probes(monkeypatch)
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    spec = IsolationSpec.confined(backend_options={LAUNCHER_OPTION: "native"}, require={REDUCED_KERNEL_SURFACE})
    plan = _plan(spec, tmp_path)
    session = session_paths(str(tmp_path / "session"))
    assert plan.argv[0] == "/usr/bin/systemd-run"
    assert "/usr/bin/bwrap" not in plan.argv
    dashdash = plan.argv.index("--")
    # The trampoline scrubs the systemd-run variables, then execs the worker command.
    assert plan.argv[dashdash + 1 : dashdash + 4] == [sys.executable, "-I", "-c"]
    trampoline = plan.argv[dashdash + 4]
    assert "XDG_RUNTIME_DIR" in trampoline and "INVOCATION_ID" in trampoline and "execv" in trampoline
    assert plan.argv[-4:] == [sys.executable, "-I", "-u", os.path.join(session["bootstrap"], "worker.py")]
    landlock = plan.policy["landlock"]
    assert landlock["required"] is True
    assert "/proc/self" in landlock["read"] and session["bootstrap"] in landlock["read"]
    assert session["work"] in landlock["write"] and session["tmp"] in landlock["write"]
    assert "/" not in landlock["read"]
    assert plan.policy["unshare_net"] == {"required": True}
    assert plan.policy["seccomp"] == {"required": True, "deny_unix_sockets": True}
    assert plan.policy["pgroup_reaper"] is True
    assert set(plan.required_applied) == {"pdeathsig", "rlimit:cpu", "landlock", "unshare_net", "seccomp"}
    report = plan.report
    assert report.missing == frozenset()
    assert report.guarantees[FILESYSTEM_ALLOWLIST] == "Landlock ABI 4 + seccomp deny socket(AF_UNIX)"
    assert report.guarantees[NO_AMBIENT_NETWORK] == "unshare(CLONE_NEWUSER|CLONE_NEWNET) + seccomp deny socket(AF_UNIX)"
    assert report.guarantees[KILLED_WITH_HOST] == "PR_SET_PDEATHSIG"
    assert "Landlock" in report.guarantees[PRIVATE_TMP]
    assert any("socket(AF_UNIX) is denied" in note for note in report.notes)
    assert any("SIGKILLs the worker's process group" in note for note in report.notes)
    assert plan.state["launcher"] == "native"


def test_plan_native_without_seccomp_machine_refuses_files_and_network(tmp_path, monkeypatch):
    _fake_probes(monkeypatch, bwrap=False, machine=None)
    with pytest.raises(IsolationUnsupportedError) as info:
        _plan(IsolationSpec.confined(), tmp_path)
    assert {FILESYSTEM_ALLOWLIST, PRIVATE_TMP, NO_AMBIENT_NETWORK} <= set(info.value.unmet)
    assert "Unix sockets" in info.value.unmet[FILESYSTEM_ALLOWLIST]
    caps = LinuxBackend().capabilities()
    assert "Unix sockets" in caps.unsupported[FILESYSTEM_ALLOWLIST]
    assert "Unix sockets" in caps.unsupported[NO_AMBIENT_NETWORK]
    # Resource caps alone do not need the rule.
    plan = _plan(IsolationSpec(limits=ResourceLimits(cpu_seconds=2)), tmp_path)
    assert plan.state["launcher"] == "native" and plan.policy["seccomp"] is None


def test_plan_rlimit_fallback_without_cgroup(tmp_path, monkeypatch):
    _fake_probes(monkeypatch, systemd=False)
    spec = IsolationSpec.confined(memory="256M", max_processes=5, backend_options={LAUNCHER_OPTION: "native"})
    plan = _plan(spec, tmp_path)
    assert plan.argv[0] == sys.executable  # no systemd-run prefix, no trampoline needed
    assert plan.policy["rlimits"]["as"] == 256 * 1024**2
    assert plan.policy["rlimits"]["nproc"] == 5
    assert "rlimit:as" in plan.required_applied and "rlimit:nproc" in plan.required_applied
    assert plan.report.guarantees[MEMORY_CAPPED] == "RLIMIT_AS"
    assert plan.report.guarantees[PROCESS_COUNT_CAPPED] == "RLIMIT_NPROC"
    assert any("cgroup limits unavailable" in note for note in plan.report.notes)
    assert "systemd_unit" not in plan.state
    assert "XDG_RUNTIME_DIR" not in plan.env


def test_plan_auto_prefers_bwrap_then_native(tmp_path, monkeypatch):
    _fake_probes(monkeypatch)
    spec = IsolationSpec.confined()
    assert _plan(spec, tmp_path).state["launcher"] == "bwrap"
    _fake_probes(monkeypatch, bwrap=False)
    plan = _plan(spec, tmp_path)
    assert plan.state["launcher"] == "native"
    assert plan.report.guarantees[FILESYSTEM_ALLOWLIST] == "Landlock ABI 4 + seccomp deny socket(AF_UNIX)"


def test_plan_files_none_binds_host_filesystem(tmp_path, monkeypatch):
    _fake_probes(monkeypatch)
    spec = IsolationSpec(network=NetworkPolicy(mode="none"), backend_options={LAUNCHER_OPTION: "bwrap"})
    plan = _plan(spec, tmp_path)
    assert plan.argv[_index_of(plan.argv, "--bind", "/") + 2] == "/"
    assert "--remount-ro" not in plan.argv
    assert plan.policy["landlock"] is None
    assert FILESYSTEM_ALLOWLIST not in plan.report.guarantees
    assert PRIVATE_TMP not in plan.report.guarantees
    assert plan.report.guarantees[NO_AMBIENT_NETWORK] == "bwrap --unshare-net"
    assert "-I" not in plan.argv  # inherited environment: no isolated mode
    assert "PATH" in plan.env


def test_plan_inherit_env_and_no_private_tmp(tmp_path, monkeypatch):
    _fake_probes(monkeypatch)
    monkeypatch.setenv("HOST_VISIBLE", "yes")
    spec = IsolationSpec(
        files=FilesystemPolicy(private_tmp=False, workdir=str(tmp_path)),
        backend_options={LAUNCHER_OPTION: "bwrap"},
    )
    plan = _plan(spec, tmp_path)
    assert plan.env["HOST_VISIBLE"] == "yes"
    assert "--tmpfs" not in plan.argv
    assert plan.cwd == str(tmp_path)
    assert plan.policy["chdir"] == str(tmp_path)
    _index_of(plan.argv, "--bind-try", str(tmp_path))
    assert PRIVATE_TMP not in plan.report.guarantees
    assert plan.report.missing == frozenset()


def test_plan_user_paths_are_kept(tmp_path, monkeypatch):
    _fake_probes(monkeypatch)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    spec = IsolationSpec.confined(read=(str(allowed),), write=(str(out),), backend_options={LAUNCHER_OPTION: "native"})
    plan = _plan(spec, tmp_path)
    assert str(allowed) in plan.policy["landlock"]["read"]
    assert str(out) in plan.policy["landlock"]["write"]


def test_refusal_when_nothing_is_available(tmp_path, monkeypatch):
    _fake_probes(monkeypatch, bwrap=False, landlock=0, userns=False)
    spec = IsolationSpec.confined()
    with pytest.raises(IsolationUnsupportedError) as info:
        _plan(spec, tmp_path)
    unmet = info.value.unmet
    assert {FILESYSTEM_ALLOWLIST, PRIVATE_TMP, NO_AMBIENT_NETWORK} <= set(unmet)
    assert "bwrap not found" in unmet[FILESYSTEM_ALLOWLIST] and "Landlock unavailable" in unmet[FILESYSTEM_ALLOWLIST]
    assert "user namespaces disabled" in unmet[NO_AMBIENT_NETWORK]
    caps = LinuxBackend().capabilities()
    assert FILESYSTEM_ALLOWLIST in caps.unsupported and NO_AMBIENT_NETWORK in caps.unsupported
    assert "apparmor_restrict_unprivileged_userns=1" in caps.unsupported[NO_AMBIENT_NETWORK]
    assert MEMORY_CAPPED in caps.supported  # rlimits still work


def test_refusal_forced_launcher(tmp_path, monkeypatch):
    _fake_probes(monkeypatch, bwrap=False)
    with pytest.raises(IsolationUnsupportedError) as info:
        _plan(IsolationSpec.confined(backend_options={LAUNCHER_OPTION: "bwrap"}), tmp_path)
    assert LAUNCHER_OPTION in info.value.unmet
    _fake_probes(monkeypatch, userns=False)
    with pytest.raises(IsolationUnsupportedError) as info:
        _plan(IsolationSpec.confined(backend_options={LAUNCHER_OPTION: "native"}), tmp_path)
    assert set(info.value.unmet) == {NO_AMBIENT_NETWORK}
    # Native mode without network confinement does not need user namespaces.
    plan = _plan(IsolationSpec.confined(network="host", backend_options={LAUNCHER_OPTION: "native"}), tmp_path)
    assert plan.policy["unshare_net"] is None and NO_AMBIENT_NETWORK not in plan.report.guarantees


def test_refusal_seccomp_on_unknown_machine(tmp_path, monkeypatch):
    _fake_probes(monkeypatch, machine=None)
    caps = LinuxBackend().capabilities()
    assert REDUCED_KERNEL_SURFACE in caps.unsupported
    plan = _plan(IsolationSpec.confined(), tmp_path)
    assert plan.policy["seccomp"] is None and REDUCED_KERNEL_SURFACE not in plan.report.guarantees
    with pytest.raises(IsolationUnsupportedError):
        _plan(IsolationSpec.confined(require={REDUCED_KERNEL_SURFACE}), tmp_path)


def test_capabilities_are_concrete(monkeypatch):
    _fake_probes(monkeypatch)
    caps = LinuxBackend().capabilities()
    assert caps.name == "linux" and caps.unsupported == {}
    assert caps.supported[FILESYSTEM_ALLOWLIST] == "bwrap bind-mount allowlist + Landlock ABI 4"
    assert caps.supported[MEMORY_CAPPED].startswith("cgroup v2")
    _fake_probes(monkeypatch, bwrap=False, systemd=False)
    caps = LinuxBackend().capabilities()
    assert caps.supported[FILESYSTEM_ALLOWLIST] == "Landlock ABI 4 + seccomp deny socket(AF_UNIX)"
    assert caps.supported[NO_AMBIENT_NETWORK] == "unshare(CLONE_NEWUSER|CLONE_NEWNET) + seccomp deny socket(AF_UNIX)"
    assert caps.supported[MEMORY_CAPPED] == "RLIMIT_AS"


def test_probe_cache_and_missing_tools(monkeypatch):
    _linux.clear_probe_cache()
    try:
        monkeypatch.setattr(_linux.shutil, "which", lambda name: None)
        assert not _linux.probe_bwrap().ok and "not found" in _linux.probe_bwrap().detail
        assert not _linux.probe_systemd_run().ok and "not found" in _linux.probe_systemd_run().detail
        # Cached: a later successful which() does not change the answer until the cache is cleared.
        monkeypatch.setattr(_linux.shutil, "which", lambda name: "/usr/bin/" + name)
        assert not _linux.probe_bwrap().ok
    finally:
        _linux.clear_probe_cache()


def test_run_probe_handles_failures(monkeypatch):
    class Timeout(subprocess.TimeoutExpired):
        pass

    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(_linux.subprocess, "run", boom)
    result = _linux._run_probe(["x"], name="x")
    assert not result.ok and "timed out" in result.detail

    class Completed:
        returncode = 3
        stdout = b""
        stderr = b"boom: no bus\n"

    monkeypatch.setattr(_linux.subprocess, "run", lambda *a, **k: Completed())
    result = _linux._run_probe(["x"], name="x")
    assert not result.ok and "status 3" in result.detail and "no bus" in result.detail


# --------------------------------------------------------------------------- #
# Live tests (Linux only, skipped when the machine cannot provide the launcher)
# --------------------------------------------------------------------------- #


def _launcher_supported(launcher: str) -> str | None:
    if not IS_LINUX:
        return "Linux only"
    if launcher == "bwrap":
        result = _linux.probe_bwrap()
        return None if result.ok else result.detail
    landlock, userns = _linux.probe_landlock_abi(), _linux.probe_userns()
    if not landlock.ok:
        return landlock.detail
    if not userns.ok:
        return userns.detail
    return None


@pytest.fixture(params=LAUNCHERS)
def launcher(request):
    reason = _launcher_supported(request.param)
    if reason:
        pytest.skip(f"{request.param}: {reason}")
    return request.param


def _confined(launcher: str, **kwargs) -> IsolationSpec:
    options = dict(kwargs.pop("backend_options", {}) or {})
    options[LAUNCHER_OPTION] = launcher
    return IsolationSpec.confined(backend_options=options, **kwargs)


def _interp(spec: IsolationSpec) -> LocalInterpreter:
    return LocalInterpreter(mode="subprocess", isolation=spec)


def _needs_seccomp():
    if _linux.seccomp_machine() is None:
        pytest.skip(f"seccomp denylist unsupported on {platform.machine()}")


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_conformance(launcher):
    spec = _confined(launcher)
    report = check_interpreter(lambda: _interp(spec))
    assert report.passed, report.to_dict()


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_report(launcher):
    interp = _interp(_confined(launcher, require={NO_NEW_PRIVILEGES, REDUCED_KERNEL_SURFACE}))
    try:
        interp.start()
        report = interp.isolation_report
        assert report is not None and report.backend == "linux"
        assert report.missing == frozenset()
        keyword = "bwrap" if launcher == "bwrap" else "Landlock"
        assert keyword in report.guarantees[FILESYSTEM_ALLOWLIST]
        assert not any("not applied" in note for note in report.notes), report.notes
        assert "separate local worker" in interp.execution_instructions
    finally:
        interp.shutdown()


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_network_denied(launcher):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    interp = _interp(_confined(launcher))
    try:
        with pytest.raises(CodeExecutionError):
            interp.execute(f"import socket\ns = socket.socket()\ns.settimeout(5)\ns.connect(('127.0.0.1', {port}))")
        assert interp.execute("import socket; sorted(name for _, name in socket.if_nameindex())") == ["lo"]
    finally:
        interp.shutdown()
        listener.close()


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_unix_socket_denied(launcher):
    """Filesystem-path and abstract Unix sockets of the host are unreachable; socketpair() still works."""
    server_dir = tempfile.mkdtemp(prefix="dspy-sock-")  # short sun_path, outside the allowlist (private tmp)
    path = os.path.join(server_dir, "host.sock")
    fs_server = socket.socket(socket.AF_UNIX)
    fs_server.bind(path)
    fs_server.listen(1)
    abstract_name = b"\0dspy-interp-" + uuid.uuid4().hex[:12].encode()
    abstract_server = socket.socket(socket.AF_UNIX)
    abstract_server.bind(abstract_name)
    abstract_server.listen(1)
    interp = _interp(_confined(launcher))
    try:
        for target in (path, abstract_name):
            code = f"import socket\ns = socket.socket(socket.AF_UNIX)\ns.settimeout(5)\ns.connect({target!r})"
            with pytest.raises(CodeExecutionError):
                interp.execute(code)
        if launcher == "native":
            with pytest.raises(CodeExecutionError, match="PermissionError"):
                interp.execute("import socket; socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)")
        code = textwrap.dedent(
            """
            import socket
            a, b = socket.socketpair()
            a.sendall(b"ping")
            out = b.recv(4)
            a.close(); b.close()
            out.decode()
            """
        )
        assert interp.execute(code) == "ping"
        assert interp.execute("import asyncio; asyncio.run(asyncio.sleep(0, result=7))") == 7
    finally:
        interp.shutdown()
        fs_server.close()
        abstract_server.close()
        os.unlink(path)
        os.rmdir(server_dir)


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_filesystem_allowlist(launcher, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "data.txt").write_text("visible")
    out = tmp_path / "out"
    out.mkdir()
    interp = _interp(_confined(launcher, read=(str(allowed),), write=(str(out),)))
    try:
        with pytest.raises(CodeExecutionError):
            interp.execute(f"open({str(secret)!r}).read()")
        assert interp.execute(f"open({str(allowed / 'data.txt')!r}).read()") == "visible"
        with pytest.raises(CodeExecutionError):
            interp.execute(f"open({str(allowed / 'new.txt')!r}, 'w').write('x')")
        assert interp.execute("open('local.txt', 'w').write('hi'); open('local.txt').read()") == "hi"
        assert interp.execute("import os; os.access(os.getcwd(), os.W_OK)") is True
        interp.execute(f"open({str(out / 'result.txt')!r}, 'w').write('done')")
        assert (out / "result.txt").read_text() == "done"
        # A write next to the allowed directories: denied (native) or lands in the private tmpfs (bwrap).
        with contextlib.suppress(CodeExecutionError):
            interp.execute(f"open({str(tmp_path / 'escape.txt')!r}, 'w').write('x')")
        assert not (tmp_path / "escape.txt").exists()
        escape = os.path.join(os.path.expanduser("~"), f".dspy-escape-{uuid.uuid4().hex}")
        with pytest.raises(CodeExecutionError):
            interp.execute(f"open({escape!r}, 'w').write('x')")
        assert not os.path.exists(escape)
        assert "/proc" not in interp.execute("import os; os.getcwd()")
        assert interp.execute("import os; open('/proc/self/status').read()[:5]") == "Name:"
    finally:
        interp.shutdown()


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_no_new_privs(launcher):
    interp = _interp(_confined(launcher, require={NO_NEW_PRIVILEGES}))
    try:
        status = interp.execute("open('/proc/self/status').read()")
        assert "NoNewPrivs:\t1" in status
    finally:
        interp.shutdown()


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_seccomp_denylist(launcher):
    _needs_seccomp()
    interp = _interp(_confined(launcher, require={REDUCED_KERNEL_SURFACE}))
    try:
        code = textwrap.dedent(
            """
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            results = {}
            rc = libc.unshare(0x10000000)
            results["unshare"] = [rc, ctypes.get_errno()]
            rc = libc.personality(0xFFFFFFFF)
            results["personality"] = [rc, ctypes.get_errno()]
            results
            """
        )
        results = interp.execute(code)
        assert results["unshare"] == [-1, 1]
        assert results["personality"] == [-1, 1]
    finally:
        interp.shutdown()


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_memory_cap(launcher):
    interp = _interp(_confined(launcher, memory="256M", wall_time_seconds=60))
    try:
        interp.execute("1")
        assert MEMORY_CAPPED in interp.isolation_report.guarantees
        with pytest.raises(CodeInterpreterError):  # MemoryError -> CodeExecutionError, or the worker is killed
            interp.execute("blob = bytearray(600 * 1024 * 1024)\nlen(blob)")
    finally:
        interp.shutdown()


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_memory_cap_rlimit_fallback(launcher, monkeypatch):
    monkeypatch.setattr(_linux, "probe_systemd_run", lambda: ProbeResult(False, "systemd-run disabled for the test"))
    interp = _interp(_confined(launcher, memory="256M", wall_time_seconds=60))
    try:
        interp.execute("1")
        assert interp.isolation_report.guarantees[MEMORY_CAPPED] == "RLIMIT_AS"
        with pytest.raises(CodeExecutionError, match="MemoryError"):
            interp.execute("blob = bytearray(600 * 1024 * 1024)\nlen(blob)")
        assert interp.execute("2 + 2") == 4  # the worker survives a MemoryError
    finally:
        interp.shutdown()


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_process_cap(launcher):
    interp = _interp(_confined(launcher, max_processes=8))
    try:
        code = textwrap.dedent(
            """
            import subprocess, sys
            procs, errors = [], []
            for _ in range(24):
                try:
                    procs.append(subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"]))
                except OSError as exc:
                    errors.append(str(exc))
                    break
            for proc in procs:
                proc.kill()
                proc.wait()
            [len(procs), errors]
            """
        )
        spawned, errors = interp.execute(code)
        assert spawned < 24 and errors, (spawned, errors)
    finally:
        interp.shutdown()


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_cpu_cap(launcher):
    interp = _interp(_confined(launcher, cpu_seconds=1, wall_time_seconds=30))
    try:
        with pytest.raises(CodeInterpreterError):
            interp.execute("while True:\n    pass")
        with pytest.raises(CodeInterpreterError):
            interp.execute("1")  # terminal
    finally:
        interp.shutdown()


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_clean_environment(launcher, monkeypatch):
    monkeypatch.setenv("DSPY_ISOLATION_SECRET", "hidden")
    monkeypatch.setenv("DSPY_ISOLATION_PASS", "shown")
    interp = _interp(_confined(launcher, env_passthrough=("DSPY_ISOLATION_PASS",)))
    try:
        env = interp.execute("import os; dict(os.environ)")
        assert "DSPY_ISOLATION_SECRET" not in env
        assert env["DSPY_ISOLATION_PASS"] == "shown"
        assert env["LANG"] == "C.UTF-8"
        assert env.get("XDG_RUNTIME_DIR") is None and env.get("DBUS_SESSION_BUS_ADDRESS") is None
        assert env.get("INVOCATION_ID") is None
        assert interp.execute("open('/proc/self/environ', 'rb').read().count(b'DSPY_ISOLATION_SECRET')") == 0
    finally:
        interp.shutdown()


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_private_tmp(launcher):
    marker = f"dspy-private-tmp-{uuid.uuid4().hex}"
    interp = _interp(_confined(launcher))
    try:
        code = textwrap.dedent(
            f"""
            import os, tempfile
            path = os.path.join(tempfile.gettempdir(), {marker!r})
            open(path, "w").write("private")
            other = tempfile.NamedTemporaryFile(delete=False)
            other.write(b"x")
            other.close()
            [tempfile.gettempdir(), os.path.exists(path), os.access("/tmp", os.W_OK) if os.path.isdir("/tmp") else None]
            """
        )
        guest_tmp, exists, tmp_writable = interp.execute(code)
        assert exists is True
        assert guest_tmp != tempfile.gettempdir() or launcher == "bwrap"
        assert not os.path.exists(os.path.join(tempfile.gettempdir(), marker))
        assert not os.path.exists(os.path.join("/tmp", marker))
        if launcher == "bwrap":
            assert tmp_writable is True
            assert interp.execute("open('/tmp/direct.txt', 'w').write('x'); 1") == 1
            assert not os.path.exists("/tmp/direct.txt")
    finally:
        interp.shutdown()


_KILL_HELPER = """
import json, os, sys
from dspy_interpreters import LocalInterpreter
from dspy_interpreters.isolation import IsolationSpec

def descendants(root):
    children = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as handle:
                stat = handle.read()
        except OSError:
            continue
        ppid = int(stat[stat.rindex(")") + 2 :].split()[1])
        children.setdefault(ppid, []).append(int(entry))
    found, stack = [], [root]
    while stack:
        pid = stack.pop()
        for child in children.get(pid, []):
            found.append(child)
            stack.append(child)
    return found

spec = IsolationSpec.confined(backend_options={"linux.launcher": sys.argv[1]})
interp = LocalInterpreter(mode="subprocess", isolation=spec)
interp.start()
assert interp.execute("6 * 7") == 42
# A guest-spawned child must not outlive the host either (bwrap: pid namespace; native: process-group reaper).
child = interp.execute("import subprocess; subprocess.Popen(['sleep', '300']).pid")
assert isinstance(child, int)
pids = descendants(os.getpid())
assert len(pids) >= 2, pids
sys.stdout.write(json.dumps({"pids": pids, "session_dir": interp._session.session_dir}) + "\\n")
sys.stdout.flush()
os._exit(0)
"""


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as handle:
            stat = handle.read()
    except OSError:
        return False
    return stat[stat.rindex(")") + 2 :].split()[0] != "Z"


@pytest.mark.skipif(not IS_LINUX, reason="Linux only")
def test_live_killed_with_host(launcher, tmp_path):
    helper = tmp_path / "host_dies.py"
    helper.write_text(_KILL_HELPER)
    completed = subprocess.run(
        [sys.executable, str(helper), launcher], capture_output=True, text=True, timeout=120, check=False
    )
    assert completed.returncode == 0, completed.stderr
    reported = json.loads(completed.stdout.strip().splitlines()[-1])
    pids = reported["pids"]
    assert pids, "helper reported no worker processes"
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and any(_alive(pid) for pid in pids):
        time.sleep(0.1)
    survivors = [pid for pid in pids if _alive(pid)]
    for pid in survivors:  # do not leak processes even when the assertion fails
        try:
            os.kill(pid, 9)
        except OSError:
            pass
    _remove_session_dir(reported["session_dir"])  # the host died without shutdown(), so nobody else cleans it
    assert not survivors, f"worker processes survived the host: {survivors}"


def _remove_session_dir(path: str) -> None:
    if not os.path.isdir(path):
        return
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            with contextlib.suppress(OSError):
                os.chmod(os.path.join(root, name), 0o700)
    shutil.rmtree(path, ignore_errors=True)
