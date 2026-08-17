"""macOS backend: pure profile/plan tests on every OS, live tests only on darwin."""

from __future__ import annotations

import os
import sys

import pytest

from dspy_interpreters.isolation import (
    CPU_TIME_CAPPED,
    FILESYSTEM_ALLOWLIST,
    KILLED_WITH_HOST,
    MEMORY_CAPPED,
    NO_AMBIENT_NETWORK,
    NO_NEW_PRIVILEGES,
    PRIVATE_TMP,
    PROCESS_COUNT_CAPPED,
    REDUCED_KERNEL_SURFACE,
    IsolationSpec,
    IsolationUnsupportedError,
    NetworkPolicy,
    ResourceLimits,
    select_backend,
)
from dspy_interpreters.isolation._backend import get_backend
from dspy_interpreters.isolation._darwin import (
    MACH_SERVICES,
    DarwinBackend,
    build_profile,
    escape_path,
)

FAKE_SANDBOX_EXEC = "/usr/bin/sandbox-exec"


def _spec(**kwargs) -> IsolationSpec:
    kwargs.setdefault("memory", None)
    return IsolationSpec.confined(**kwargs)


def _session(tmp_path):
    session = tmp_path / "session"
    for name in ("bootstrap", "work", "tmp"):
        (session / name).mkdir(parents=True)
    worker = session / "bootstrap" / "worker.py"
    worker.write_text("print('worker')\n")
    return str(session), str(worker)


# --------------------------------------------------------------------------- #
# build_profile (pure)
# --------------------------------------------------------------------------- #


def test_profile_header_and_fixed_rules(tmp_path):
    profile = build_profile(_spec(), read_paths=[str(tmp_path)], write_paths=[], network_allowed=False)
    lines = profile.splitlines()
    assert lines[0] == "(version 1)"
    assert lines[1] == "(deny default)"
    assert "(allow file-read-metadata)" in lines
    assert "(allow process-fork)" in lines
    assert "(allow signal (target self))" in lines
    assert "(allow sysctl-read)" in lines
    assert "(allow ipc-posix-shm)" in lines
    assert '(allow file-read* file-write-data file-ioctl (literal "/dev/dtracehelper") (literal "/dev/null"))' in lines
    assert '(allow file-write* (literal "/dev/null"))' in lines
    mach = next(line for line in lines if line.startswith("(allow mach-lookup"))
    for name in MACH_SERVICES:
        assert f'(global-name "{name}")' in mach
    assert profile.endswith("\n")


def test_profile_network_rules(tmp_path):
    denied = build_profile(_spec(), read_paths=[str(tmp_path)], write_paths=[], network_allowed=False)
    allowed = build_profile(_spec(), read_paths=[str(tmp_path)], write_paths=[], network_allowed=True)
    assert "(deny network*)" in denied.splitlines()
    assert "(allow network*)" not in denied
    assert "(allow network*)" in allowed.splitlines()
    assert "(deny network*)" not in allowed


def test_profile_read_write_paths_use_subpath_for_dirs_and_literal_for_files(tmp_path):
    read_dir = tmp_path / "data"
    read_dir.mkdir()
    read_file = tmp_path / "config.json"
    read_file.write_text("{}")
    write_dir = tmp_path / "out"
    write_dir.mkdir()
    write_file = tmp_path / "log.txt"
    write_file.write_text("")
    profile = build_profile(
        _spec(),
        read_paths=[str(read_dir), str(read_file)],
        write_paths=[str(write_dir), str(write_file)],
        network_allowed=False,
    )
    lines = profile.splitlines()
    read_rules = [line for line in lines if line.startswith("(allow file-read* (")]
    # SBPL file-write* does not include file-read*: write paths get both operations.
    write_rules = [line for line in lines if line.startswith("(allow file-read* file-write* (")]
    assert len(read_rules) == 1 and len(write_rules) == 1
    read_rule, write_rule = read_rules[0], write_rules[0]
    assert f'(subpath "{read_dir}")' in read_rule
    assert f'(literal "{read_file}")' in read_rule
    assert f'(subpath "{write_dir}")' in write_rule
    assert f'(literal "{write_file}")' in write_rule
    # No cross-contamination between the read and write allowlists.
    assert str(write_dir) not in read_rule
    assert str(read_dir) not in write_rule
    # process-exec defaults to the read paths.
    exec_rule = next(line for line in lines if line.startswith("(allow process-exec "))
    assert f'(subpath "{read_dir}")' in exec_rule
    assert str(write_dir) not in exec_rule


def test_profile_escapes_quotes_and_backslashes(tmp_path):
    weird = tmp_path / 'we"ird\\dir'
    weird.mkdir()
    profile = build_profile(_spec(), read_paths=[str(weird)], write_paths=[], network_allowed=False)
    escaped = escape_path(str(weird))
    assert escaped.endswith('we\\"ird\\\\dir')
    assert f'(subpath "{escaped}")' in profile
    assert f'(subpath "{weird}")' not in profile


def test_escape_path():
    assert escape_path('/a"b') == '/a\\"b'
    assert escape_path("/a\\b") == "/a\\\\b"
    assert escape_path("/plain/path") == "/plain/path"


def test_profile_extra_is_appended_last(tmp_path):
    extra = '(allow mach-lookup (global-name "com.example.test"))'
    spec = _spec(backend_options={"darwin.profile_extra": extra})
    profile = build_profile(spec, read_paths=[str(tmp_path)], write_paths=[], network_allowed=False)
    lines = profile.strip().splitlines()
    assert lines[-1] == extra
    assert lines[-2] == "(deny network*)"


def test_profile_without_extra_ends_with_network_rule(tmp_path):
    profile = build_profile(_spec(), read_paths=[str(tmp_path)], write_paths=[], network_allowed=True)
    assert profile.strip().splitlines()[-1] == "(allow network*)"


def test_profile_omits_empty_read_or_write_rules():
    profile = build_profile(_spec(), read_paths=[], write_paths=[], network_allowed=False)
    lines = profile.splitlines()
    assert not any(line.startswith("(allow file-read* (") for line in lines)
    assert not any(line.startswith("(allow file-read* file-write* (") for line in lines)
    assert not any(line.startswith("(allow file-write* (") and "/dev/null" not in line for line in lines)
    assert not any(line.startswith("(allow process-exec ") for line in lines)
    assert "(deny default)" in lines


# --------------------------------------------------------------------------- #
# capabilities and selection (no shell-out off darwin)
# --------------------------------------------------------------------------- #


def test_capabilities_do_not_shell_out_off_darwin(monkeypatch):
    import subprocess

    def boom(*args, **kwargs):  # pragma: no cover - only hit on a defect
        raise AssertionError("capabilities() must not run a subprocess")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    caps = DarwinBackend().capabilities()
    assert caps.name == DarwinBackend.name
    assert caps.platform == "darwin"
    assert caps.unsupported[MEMORY_CAPPED] == "macOS does not enforce RLIMIT_AS; no cgroup equivalent"
    assert NO_NEW_PRIVILEGES in caps.unsupported
    assert REDUCED_KERNEL_SURFACE in caps.unsupported
    assert MEMORY_CAPPED not in caps.supported
    assert caps.supported[CPU_TIME_CAPPED] == "RLIMIT_CPU"
    assert "RLIMIT_NPROC" in caps.supported[PROCESS_COUNT_CAPPED]
    assert "watchdog" in caps.supported[KILLED_WITH_HOST]
    assert any("experimental" in note for note in caps.notes)


def test_capabilities_are_cached():
    backend = DarwinBackend()
    assert backend.capabilities() is backend.capabilities()


def test_capabilities_with_sandbox_exec_present():
    caps = DarwinBackend(sandbox_exec=FAKE_SANDBOX_EXEC).capabilities()
    assert FILESYSTEM_ALLOWLIST in caps.supported
    assert NO_AMBIENT_NETWORK in caps.supported
    assert PRIVATE_TMP in caps.supported
    assert MEMORY_CAPPED in caps.unsupported


def test_capabilities_without_sandbox_exec(monkeypatch):
    monkeypatch.setattr("dspy_interpreters.isolation._darwin.locate_sandbox_exec", lambda: None)
    caps = DarwinBackend().capabilities()
    assert caps.unsupported[FILESYSTEM_ALLOWLIST] == "sandbox-exec not found"
    assert caps.unsupported[NO_AMBIENT_NETWORK] == "sandbox-exec not found"


def test_get_backend_darwin_returns_darwin_backend():
    assert isinstance(get_backend("darwin"), DarwinBackend)


def test_select_backend_refuses_memory_on_darwin():
    spec = IsolationSpec(limits=ResourceLimits(memory="256M"))
    with pytest.raises(IsolationUnsupportedError) as info:
        select_backend(spec, platform="darwin")
    assert info.value.backend == DarwinBackend.name
    assert info.value.unmet[MEMORY_CAPPED] == "macOS does not enforce RLIMIT_AS; no cgroup equivalent"
    assert "memory_capped" in str(info.value)


def test_select_backend_darwin_accepts_cpu_and_process_caps():
    spec = IsolationSpec(limits=ResourceLimits(cpu_seconds=5, max_processes=4))
    assert isinstance(select_backend(spec, platform="darwin"), DarwinBackend)


# --------------------------------------------------------------------------- #
# plan (pure; sandbox-exec path injected)
# --------------------------------------------------------------------------- #


def test_plan_refuses_memory(tmp_path):
    session, worker = _session(tmp_path)
    backend = DarwinBackend(sandbox_exec=FAKE_SANDBOX_EXEC)
    with pytest.raises(IsolationUnsupportedError) as info:
        spec = IsolationSpec.confined(memory="1G")
        backend.plan(spec, python=sys.executable, worker_path=worker, session_dir=session)
    assert MEMORY_CAPPED in info.value.unmet


def test_plan_argv_shape_and_policy(tmp_path):
    session, worker = _session(tmp_path)
    read_dir = tmp_path / "input"
    read_dir.mkdir()
    spec = _spec(read=(str(read_dir),), cpu_seconds=10, max_processes=8)
    plan = DarwinBackend(sandbox_exec=FAKE_SANDBOX_EXEC).plan(
        spec, python=sys.executable, worker_path=worker, session_dir=session
    )
    assert plan.argv[0] == FAKE_SANDBOX_EXEC
    assert plan.argv[1] == "-p"
    profile = plan.argv[2]
    assert plan.argv[3] == "--"
    assert plan.argv[4:] == [sys.executable, "-I", "-u", worker]
    assert profile.startswith("(version 1)\n(deny default)\n")
    assert "(deny network*)" in profile
    assert f'(subpath "{read_dir}")' in profile
    assert f'(subpath "{os.path.join(session, "bootstrap")}")' in profile
    assert f'(subpath "{os.path.join(session, "work")}")' in profile
    assert f'(subpath "{os.path.join(session, "tmp")}")' in profile
    # Policy: cpu and nproc rlimits, never "as"; nothing Linux-only.
    assert plan.policy["rlimits"]["cpu"] == 11
    assert plan.policy["rlimits"]["nproc"] == 8
    assert plan.policy["rlimits"]["core"] == 0
    assert "as" not in plan.policy["rlimits"]
    assert plan.policy["landlock"] is None
    assert plan.policy["unshare_net"] is None
    assert plan.policy["no_new_privs"] is None
    assert plan.policy["seccomp"] is None
    assert plan.policy["chdir"] == os.path.join(session, "work")
    assert plan.cwd == os.path.join(session, "work")
    assert plan.popen_kwargs == {"start_new_session": True}
    assert set(plan.required_applied) == {"ppid_watchdog", "rlimit:cpu", "rlimit:nproc"}
    # Environment is clean and points TMPDIR at the private directory.
    assert plan.env["TMPDIR"] == os.path.join(session, "tmp")
    assert "HOME" in plan.env
    assert plan.env.get("PYTHONDONTWRITEBYTECODE") == "1"


def test_plan_report_lists_mechanisms_and_experimental_note(tmp_path):
    session, worker = _session(tmp_path)
    spec = _spec(cpu_seconds=10, max_processes=8)
    plan = DarwinBackend(sandbox_exec=FAKE_SANDBOX_EXEC).plan(
        spec, python=sys.executable, worker_path=worker, session_dir=session
    )
    report = plan.report
    assert report.backend == DarwinBackend.name
    assert report.platform == "darwin"
    assert report.missing == frozenset()
    assert report.guarantees[FILESYSTEM_ALLOWLIST].startswith("sandbox-exec")
    assert report.guarantees[NO_AMBIENT_NETWORK] == "sandbox-exec (deny network*)"
    assert report.guarantees[CPU_TIME_CAPPED] == "RLIMIT_CPU"
    assert "RLIMIT_NPROC" in report.guarantees[PROCESS_COUNT_CAPPED]
    assert "watchdog" in report.guarantees[KILLED_WITH_HOST]
    assert PRIVATE_TMP in report.guarantees
    assert MEMORY_CAPPED not in report.guarantees
    assert any("experimental" in note for note in report.notes)
    assert any("RLIMIT_NPROC" in note for note in report.notes)


def test_plan_network_host_allows_network(tmp_path):
    session, worker = _session(tmp_path)
    plan = DarwinBackend(sandbox_exec=FAKE_SANDBOX_EXEC).plan(
        _spec(network="host"), python=sys.executable, worker_path=worker, session_dir=session
    )
    assert "(allow network*)" in plan.argv[2]
    assert NO_AMBIENT_NETWORK not in plan.report.guarantees


def test_plan_without_files_or_network_skips_sandbox_exec(tmp_path):
    session, worker = _session(tmp_path)
    spec = IsolationSpec(limits=ResourceLimits(cpu_seconds=3))
    plan = DarwinBackend(sandbox_exec=FAKE_SANDBOX_EXEC).plan(
        spec, python=sys.executable, worker_path=worker, session_dir=session
    )
    assert plan.argv == [sys.executable, "-u", worker]
    assert plan.policy["rlimits"]["cpu"] == 4
    assert plan.required_applied == ("ppid_watchdog", "rlimit:cpu")
    assert FILESYSTEM_ALLOWLIST not in plan.report.guarantees


def test_plan_profile_extra_last(tmp_path):
    session, worker = _session(tmp_path)
    spec = _spec(backend_options={"darwin.profile_extra": "(allow sysctl*)"})
    plan = DarwinBackend(sandbox_exec=FAKE_SANDBOX_EXEC).plan(
        spec, python=sys.executable, worker_path=worker, session_dir=session
    )
    assert plan.argv[2].strip().splitlines()[-1] == "(allow sysctl*)"


def test_plan_write_paths_and_workdir(tmp_path):
    session, worker = _session(tmp_path)
    workdir = tmp_path / "project"
    workdir.mkdir()
    extra_write = tmp_path / "scratch"
    extra_write.mkdir()
    spec = _spec(workdir=str(workdir), write=(str(extra_write),))
    plan = DarwinBackend(sandbox_exec=FAKE_SANDBOX_EXEC).plan(
        spec, python=sys.executable, worker_path=worker, session_dir=session
    )
    lines = plan.argv[2].splitlines()
    write_rule = next(line for line in lines if line.startswith("(allow file-read* file-write* ("))
    assert f'(subpath "{workdir}")' in write_rule
    assert f'(subpath "{extra_write}")' in write_rule
    # The session tmp is readable through the write rule, not through a blanket /var grant.
    assert f'(subpath "{os.path.join(session, "tmp")}")' in write_rule
    assert plan.cwd == str(workdir)
    assert plan.policy["chdir"] == str(workdir)


def test_read_allowlist_excludes_var(tmp_path):
    """/var/folders holds $TMPDIR (host temp files, other sessions' work dirs): never a blanket read grant."""
    from dspy_interpreters.isolation._backend import system_read_paths

    for path in system_read_paths("darwin"):
        assert path not in ("/var", "/private/var", "/private/var/folders", "/private/var/tmp")
    assert "/private/var/db/dyld" in system_read_paths("darwin")
    session, worker = _session(tmp_path)
    plan = DarwinBackend(sandbox_exec=FAKE_SANDBOX_EXEC).plan(
        _spec(), python=sys.executable, worker_path=worker, session_dir=session
    )
    profile = plan.argv[2]
    assert '(subpath "/var")' not in profile and '(subpath "/private/var")' not in profile


def test_profile_network_mach_services_and_posix_sem(tmp_path):
    from dspy_interpreters.isolation._darwin import NETWORK_MACH_SERVICES

    denied = build_profile(_spec(), read_paths=[str(tmp_path)], write_paths=[], network_allowed=False)
    allowed = build_profile(_spec(), read_paths=[str(tmp_path)], write_paths=[], network_allowed=True)
    for name in NETWORK_MACH_SERVICES:
        assert f'(global-name "{name}")' in allowed
        assert f'(global-name "{name}")' not in denied
    assert "(allow ipc-posix-sem)" in denied.splitlines()


def test_plan_network_only_does_not_restrict_exec(tmp_path):
    session, worker = _session(tmp_path)
    spec = IsolationSpec(network=NetworkPolicy(mode="none"))
    plan = DarwinBackend(sandbox_exec=FAKE_SANDBOX_EXEC).plan(
        spec, python=sys.executable, worker_path=worker, session_dir=session
    )
    lines = plan.argv[2].splitlines()
    exec_rule = next(line for line in lines if line.startswith("(allow process-exec "))
    assert '(subpath "/")' in exec_rule
    assert "(deny network*)" in lines


def test_kill_uses_killpg(monkeypatch):
    calls = []

    class FakeProcess:
        pid = 4242

        def kill(self):
            calls.append("kill")

    def fake_killpg(pgid, sig):
        calls.append(("killpg", pgid, sig))

    monkeypatch.setattr(os, "killpg", fake_killpg)
    import signal

    from dspy_interpreters.isolation._backend import LaunchPlan

    DarwinBackend().kill(FakeProcess(), LaunchPlan(argv=[], env={}, cwd=None, policy={}, report=None))
    assert calls[0] == ("killpg", 4242, signal.SIGKILL)
    assert "kill" in calls


# --------------------------------------------------------------------------- #
# Live (macOS only)
# --------------------------------------------------------------------------- #

darwin_only = pytest.mark.skipif(sys.platform != "darwin", reason="requires macOS sandbox-exec")


@darwin_only
def test_live_sandbox_exec_probe():
    caps = DarwinBackend().capabilities()
    assert FILESYSTEM_ALLOWLIST in caps.supported, caps.to_dict()


@darwin_only
def test_live_confined_subprocess_denies_network_and_outside_reads(tmp_path):
    from dspy import CodeExecutionError

    from dspy_interpreters import LocalInterpreter

    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    spec = IsolationSpec.confined(memory=None, wall_time_seconds=60)
    interpreter = LocalInterpreter(mode="subprocess", isolation=spec)
    interpreter.start()
    try:
        assert interpreter.execute("1 + 1") == 2
        with pytest.raises(CodeExecutionError):
            interpreter.execute(f"open({str(secret)!r}).read()")
        with pytest.raises(CodeExecutionError):
            interpreter.execute("import socket; socket.create_connection(('1.1.1.1', 53), timeout=3)")
        assert interpreter.execute("import os; open('ok.txt', 'w').write('x'); os.path.exists('ok.txt')") is True
        assert interpreter.execute("open('ok.txt').read()") == "x"
        assert interpreter.execute("import os; 'ok.txt' in os.listdir('.')") is True
        code = (
            "import tempfile\nf = tempfile.NamedTemporaryFile()\nf.write(b'y'); f.flush(); f.seek(0)\nf.read().decode()"
        )
        assert interpreter.execute(code) == "y"
        assert interpreter.isolation_report is not None
        assert FILESYSTEM_ALLOWLIST in interpreter.isolation_report.guarantees
    finally:
        interpreter.shutdown()
