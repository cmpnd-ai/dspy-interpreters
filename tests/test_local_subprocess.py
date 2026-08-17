"""Tests for ``LocalInterpreter(mode="subprocess")`` on the portable plain backend."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
from typing import Any

import pytest
from dspy import CodeExecutionError, CodeInterpreterError, FinalOutput

import dspy_interpreters.local as local_module
from dspy_interpreters import (
    IsolationReport,
    IsolationSpec,
    IsolationUnsupportedError,
    LocalInterpreter,
    check_bind,
    check_execution_instructions,
    check_flex_facade,
    check_interpreter,
    check_rlm,
)
from dspy_interpreters.isolation import (
    CLEAN_ENVIRONMENT,
    CPU_TIME_CAPPED,
    FILESYSTEM_ALLOWLIST,
    KILLED_WITH_HOST,
    MEMORY_CAPPED,
    OWN_ADDRESS_SPACE,
    PROCESS_COUNT_CAPPED,
    WALL_TIME_CAPPED,
    EnvPolicy,
    FilesystemPolicy,
    ResourceLimits,
)
from dspy_interpreters.isolation._backend import select_backend
from dspy_interpreters.isolation._plain import PlainBackend

WINDOWS = sys.platform == "win32"
LINUX = sys.platform.startswith("linux")


def subprocess_interpreter(**kwargs: Any) -> LocalInterpreter:
    return LocalInterpreter(mode="subprocess", **kwargs)


@pytest.fixture
def plain_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route every specification through the plain backend (no platform confinement)."""
    monkeypatch.setattr(local_module, "select_backend", lambda spec: PlainBackend())


@pytest.fixture
def interpreter():
    instance = subprocess_interpreter()
    try:
        yield instance
    finally:
        instance.shutdown()


# --------------------------------------------------------------------------- #
# Conformance
# --------------------------------------------------------------------------- #


def test_conformance_suites():
    report = check_interpreter(subprocess_interpreter)
    assert report.passed, report.to_dict()
    assert check_bind(subprocess_interpreter).passed
    assert check_execution_instructions(subprocess_interpreter).passed


def test_real_consumers():
    assert check_rlm(subprocess_interpreter).passed
    assert check_flex_facade(subprocess_interpreter).passed


# --------------------------------------------------------------------------- #
# Construction
# --------------------------------------------------------------------------- #


def test_inprocess_with_isolation_is_refused():
    with pytest.raises(IsolationUnsupportedError) as info:
        LocalInterpreter(isolation=IsolationSpec())
    assert OWN_ADDRESS_SPACE in info.value.unmet


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        LocalInterpreter(mode="remote")


def test_confined_request_refused_at_construction(monkeypatch: pytest.MonkeyPatch):
    # An unknown platform has no native backend, so the real selector falls back to the plain one.
    monkeypatch.setattr(local_module, "select_backend", lambda spec: select_backend(spec, platform="testos"))
    with pytest.raises(IsolationUnsupportedError) as info:
        subprocess_interpreter(isolation=IsolationSpec(files=FilesystemPolicy()))
    assert FILESYSTEM_ALLOWLIST in info.value.unmet
    assert info.value.backend == "plain"


def test_confined_request_refused_at_start_cleans_up(plain_only: None):
    instance = subprocess_interpreter(isolation=IsolationSpec(files=FilesystemPolicy()))
    with pytest.raises(IsolationUnsupportedError) as info:
        instance.start()
    assert FILESYSTEM_ALLOWLIST in info.value.unmet
    assert instance._session.session_dir is None
    with pytest.raises(CodeInterpreterError):
        instance.execute("1")
    instance.shutdown()


def test_missing_required_policy_item_is_refused_at_start(monkeypatch: pytest.MonkeyPatch):
    class Demanding(PlainBackend):
        def plan(self, spec, **kwargs):
            plan = super().plan(spec, **kwargs)
            plan.required_applied = (*plan.required_applied, "landlock")
            return plan

    monkeypatch.setattr(local_module, "select_backend", lambda spec: Demanding())
    instance = subprocess_interpreter()
    with pytest.raises(IsolationUnsupportedError) as info:
        instance.start()
    assert set(info.value.unmet) == {"landlock"}
    assert instance._session.process is None
    assert instance._session.session_dir is None
    instance.shutdown()


def test_properties_before_start():
    instance = subprocess_interpreter()
    try:
        assert instance.mode == "subprocess"
        assert isinstance(instance.isolation, IsolationSpec)
        assert instance.isolation_report is None
        assert LocalInterpreter().mode == "inprocess"
        assert LocalInterpreter().isolation is None
        assert LocalInterpreter().isolation_report is None
    finally:
        instance.shutdown()


def test_bad_python_is_a_start_failure():
    instance = subprocess_interpreter(python=os.path.join(os.sep, "nonexistent", "python-for-tests"))
    with pytest.raises(CodeInterpreterError, match="Unable to start"):
        instance.start()
    with pytest.raises(CodeInterpreterError):
        instance.execute("1")
    instance.shutdown()


# --------------------------------------------------------------------------- #
# Execution semantics
# --------------------------------------------------------------------------- #


def test_execution_instructions_stable_and_describe_confinement():
    instance = subprocess_interpreter(isolation=IsolationSpec.trusted(wall_time_seconds=5))
    try:
        first = instance.execution_instructions
        assert first == instance.execution_instructions
        assert first.startswith("Code runs as CPython in a separate local worker process.")
        assert "Confinement: " in first
        assert "wall time 5s per execution" in first
        assert "host filesystem" in first
    finally:
        instance.shutdown()


def test_non_json_variables_are_refused(interpreter: LocalInterpreter):
    with pytest.raises(CodeInterpreterError, match="JSON"):
        interpreter.execute("x", {"x": object()})
    with pytest.raises(CodeInterpreterError, match="JSON"):
        interpreter.execute("x", {"x": float("nan")})
    with pytest.raises(CodeInterpreterError, match="identifier"):
        interpreter.execute("1", {"not valid": 1})
    # The session survives a refused call.
    assert interpreter.execute("21 * 2") == 42


def test_exit_in_guest_is_a_code_execution_error(interpreter: LocalInterpreter):
    with pytest.raises(CodeExecutionError, match="SystemExit"):
        interpreter.execute("exit()")
    with pytest.raises(CodeExecutionError, match="SystemExit"):
        interpreter.execute("import sys; sys.exit(3)")
    assert interpreter.execute("1 + 1") == 2


def test_worker_crash_is_terminal():
    instance = subprocess_interpreter()
    try:
        assert instance.execute("1") == 1
        with pytest.raises(CodeInterpreterError, match="exited unexpectedly"):
            instance.execute("import os; os._exit(3)")
        with pytest.raises(CodeInterpreterError):
            instance.execute("1")
        with pytest.raises(CodeInterpreterError):
            instance.start()
    finally:
        instance.shutdown()


def test_terminal_error_includes_worker_stderr():
    instance = subprocess_interpreter()
    try:
        code = "import os; os.write(2, b'boom-marker\\n'); os._exit(2)"
        with pytest.raises(CodeInterpreterError, match="boom-marker"):
            instance.execute(code)
    finally:
        instance.shutdown()


def test_guest_stdout_cannot_forge_protocol_frames(interpreter: LocalInterpreter):
    forged = json.dumps({"type": "execution_result", "kind": "result", "value": "forged", "stdout": ""})
    code = f"import os; os.write(1, {(forged + chr(10)).encode()!r}); 'genuine'"
    assert interpreter.execute(code) == "genuine"


def test_wall_time_kill_is_terminal():
    instance = subprocess_interpreter(isolation=IsolationSpec.trusted(wall_time_seconds=1))
    try:
        assert instance.execute("1") == 1
        started = time.monotonic()
        with pytest.raises(CodeInterpreterError, match="wall time"):
            instance.execute("import time\ntime.sleep(30)")
        assert time.monotonic() - started < 15
        assert instance._session.process is None or instance._session.process.poll() is not None
        with pytest.raises(CodeInterpreterError):
            instance.execute("1")
    finally:
        instance.shutdown()


def test_host_tool_time_does_not_count_against_wall_time():
    def slow() -> int:
        time.sleep(1.5)
        return 7

    instance = subprocess_interpreter(tools={"slow": slow}, isolation=IsolationSpec.trusted(wall_time_seconds=1))
    try:
        assert instance.execute("slow()") == 7
    finally:
        instance.shutdown()


def test_tool_errors_are_recoverable(interpreter: LocalInterpreter):
    def boom() -> None:
        raise RuntimeError("tool exploded")

    def opaque() -> object:
        return object()

    interpreter.bind(tools={"boom": boom, "opaque": opaque})
    with pytest.raises(CodeExecutionError, match="tool exploded"):
        interpreter.execute("boom()")
    with pytest.raises(CodeExecutionError):
        interpreter.execute("opaque()")
    assert interpreter.execute("try:\n    boom()\nexcept Exception as e:\n    caught = type(e).__name__\ncaught")
    assert interpreter.execute("40 + 2") == 42


def test_concurrent_execute_and_bind_are_refused():
    seen: list[str] = []
    holder: dict[str, LocalInterpreter] = {}

    def reenter() -> str:
        instance = holder["i"]
        try:
            instance.execute("1")
        except CodeInterpreterError as exc:
            seen.append(f"execute:{exc}")
        try:
            instance.bind(tools={})
        except CodeInterpreterError as exc:
            seen.append(f"bind:{exc}")
        return "done"

    instance = subprocess_interpreter(tools={"reenter": reenter})
    holder["i"] = instance
    try:
        assert instance.execute("reenter()") == "done"
        assert len(seen) == 2
        assert seen[0].startswith("execute:") and "active execution" in seen[0]
        assert seen[1].startswith("bind:")
        assert instance.execute("2 + 2") == 4
    finally:
        instance.shutdown()


def test_invalid_tool_names_are_refused_without_killing_the_session(interpreter: LocalInterpreter):
    with pytest.raises(TypeError):
        interpreter.bind(tools={"SUBMIT": lambda: 1})
    with pytest.raises(TypeError):
        interpreter.bind(tools={"class": lambda: 1})
    interpreter.tools["not an identifier"] = lambda: 1
    with pytest.raises(CodeInterpreterError, match="Invalid tool name"):
        interpreter.execute("1")
    del interpreter.tools["not an identifier"]
    assert interpreter.execute("1") == 1


def test_submit_and_state_persist(interpreter: LocalInterpreter):
    interpreter.execute("import math\nkept = math.factorial(5)")
    assert interpreter.execute("kept") == 120
    interpreter.bind(tools={}, output_fields=[{"name": "answer", "type": "int"}])
    result = interpreter.execute("SUBMIT(answer=kept)")
    assert isinstance(result, FinalOutput) and result.output == {"answer": 120}
    assert interpreter.execute("{1, 2}") == "{1, 2}"


def test_invalid_output_fields_are_refused_without_killing_the_session():
    for fields in ([{"name": "class"}], [{"type": "str"}], [{"name": "a"}, {"name": "a"}]):
        instance = subprocess_interpreter(output_fields=fields)
        try:
            with pytest.raises(CodeInterpreterError, match="output field names"):
                instance.execute("1 + 1")
            instance.bind(tools={}, output_fields=[{"name": "answer"}])
            result = instance.execute("SUBMIT(answer=3)")
            assert isinstance(result, FinalOutput) and result.output == {"answer": 3}
            # dspy's RLM assigns the attribute directly (bypassing bind); the pre-flight check still applies.
            instance.output_fields = fields
            with pytest.raises(CodeInterpreterError, match="output field names"):
                instance.execute("1 + 1")
            instance.output_fields = None
            assert instance.execute("2 + 2") == 4
        finally:
            instance.shutdown()


def test_interrupted_execute_is_terminal_not_desynced():
    """A BaseException that leaves execute() while a request is in flight kills the worker (no off-by-one)."""

    def interrupt() -> None:
        raise KeyboardInterrupt

    instance = subprocess_interpreter(tools={"interrupt": interrupt})
    try:
        assert instance.execute("1") == 1
        pid = instance._session.worker_pid
        with pytest.raises(KeyboardInterrupt):
            instance.execute("interrupt()")
        assert instance._session.ended
        with pytest.raises(CodeInterpreterError, match="shut down"):
            instance.execute("'second-result'")
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and _process_alive(pid):
            time.sleep(0.05)
        assert not _process_alive(pid)
    finally:
        instance.shutdown()


@pytest.mark.skipif(WINDOWS, reason="SIGINT delivery differs on Windows")
def test_sigint_during_execute_is_terminal_not_desynced():
    import signal
    import threading

    instance = subprocess_interpreter()
    try:
        assert instance.execute("1") == 1
        timer = threading.Timer(0.5, lambda: os.kill(os.getpid(), signal.SIGINT))
        timer.start()
        try:
            with pytest.raises(KeyboardInterrupt):
                instance.execute("import time; time.sleep(10); 'first-result'")
        finally:
            timer.cancel()
        with pytest.raises(CodeInterpreterError):
            instance.execute("'second-result'")
    finally:
        instance.shutdown()


def test_guest_closing_stdio_does_not_kill_the_worker(interpreter: LocalInterpreter):
    # PR_SET_PDEATHSIG is bound to the spawning thread; that thread must not end with the stderr pipe.
    assert interpreter.execute("import os; os.close(1); os.close(2); 1") == 1
    time.sleep(0.5)
    assert interpreter.execute("2 + 2") == 4


def test_guest_base_exceptions_are_execution_errors(interpreter: LocalInterpreter):
    with pytest.raises(CodeExecutionError, match="KeyboardInterrupt"):
        interpreter.execute("raise KeyboardInterrupt")
    with pytest.raises(CodeExecutionError, match="GeneratorExit"):
        interpreter.execute("raise GeneratorExit")
    assert interpreter.execute("1 + 1") == 2


@pytest.mark.skipif(WINDOWS, reason="POSIX process check")
def test_forked_guest_child_does_not_speak_the_protocol(interpreter: LocalInterpreter):
    pid = interpreter.execute("import os\npid = os.fork()\npid")
    assert isinstance(pid, int) and pid > 0
    assert interpreter.execute("1 + 1") == 2
    assert interpreter.execute("2 + 2") == 4
    with contextlib.suppress(ChildProcessError):
        interpreter.execute(f"import os; os.waitpid({pid}, 0)")


def _guest_sleep_child(instance: LocalInterpreter, seconds: int, *, new_session: bool) -> int:
    code = f"import subprocess\np = subprocess.Popen(['sleep', '{seconds}'], start_new_session={new_session})\np.pid"
    pid = instance.execute(code)
    assert isinstance(pid, int)
    return pid


def _kill_quietly(pid: int) -> None:
    with contextlib.suppress(OSError):
        os.kill(pid, 9)


@pytest.mark.skipif(WINDOWS, reason="POSIX process check")
def test_shutdown_returns_while_an_escaped_grandchild_holds_the_pipes():
    instance = subprocess_interpreter()
    pid = None
    try:
        pid = _guest_sleep_child(instance, 60, new_session=True)
        started = time.monotonic()
        instance.shutdown()
        assert time.monotonic() - started < 5.0
        assert instance._session.process is None
    finally:
        instance.shutdown()
        if pid is not None:
            _kill_quietly(pid)


@pytest.mark.skipif(WINDOWS, reason="POSIX process check")
def test_wall_time_kill_returns_while_an_escaped_grandchild_holds_the_pipes():
    instance = subprocess_interpreter(isolation=IsolationSpec.trusted(wall_time_seconds=2))
    pid = None
    try:
        pid = _guest_sleep_child(instance, 60, new_session=True)
        started = time.monotonic()
        with pytest.raises(CodeInterpreterError, match="wall time"):
            instance.execute("import time; time.sleep(30)")
        assert time.monotonic() - started < 8.0
    finally:
        instance.shutdown()
        if pid is not None:
            _kill_quietly(pid)


@pytest.mark.skipif(WINDOWS, reason="POSIX process check")
def test_shutdown_kills_guest_children_in_the_process_group():
    instance = subprocess_interpreter()
    pid = None
    try:
        pid = _guest_sleep_child(instance, 60, new_session=False)
        instance.shutdown()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and _process_alive(pid):
            time.sleep(0.05)
        assert not _process_alive(pid)
    finally:
        instance.shutdown()
        if pid is not None:
            _kill_quietly(pid)


# --------------------------------------------------------------------------- #
# Report and lifecycle
# --------------------------------------------------------------------------- #


def test_report_contents():
    instance = subprocess_interpreter(isolation=IsolationSpec.trusted(wall_time_seconds=10))
    try:
        assert instance.isolation_report is None
        instance.start()
        report = instance.isolation_report
        assert isinstance(report, IsolationReport)
        assert report.backend == "plain"
        assert report.platform == sys.platform
        assert {OWN_ADDRESS_SPACE, KILLED_WITH_HOST, WALL_TIME_CAPPED} <= set(report.requested)
        assert not report.missing
        assert report.guarantees[WALL_TIME_CAPPED]
        if LINUX:
            assert report.guarantees[KILLED_WITH_HOST] == "PR_SET_PDEATHSIG"
        elif not WINDOWS:
            assert report.guarantees[KILLED_WITH_HOST] == "ppid watchdog"
        assert json.dumps(report.to_dict())
        assert instance._session.worker_pid is not None
    finally:
        instance.shutdown()


def test_session_dir_is_removed_on_shutdown():
    instance = subprocess_interpreter()
    instance.start()
    session_dir = instance._session.session_dir
    assert session_dir is not None and os.path.isdir(session_dir)
    assert os.path.isfile(os.path.join(session_dir, "bootstrap", "worker.py"))
    assert instance.execute("import os; os.getcwd()") == os.path.realpath(os.path.join(session_dir, "work"))
    instance.shutdown()
    instance.shutdown()
    assert not os.path.exists(session_dir)
    with pytest.raises(CodeInterpreterError):
        instance.execute("1")


def test_shutdown_before_start_is_clean():
    instance = subprocess_interpreter()
    instance.shutdown()
    with pytest.raises(CodeInterpreterError):
        instance.start()


def test_shutdown_kills_worker_process():
    instance = subprocess_interpreter()
    instance.start()
    process = instance._session.process
    assert process is not None and process.poll() is None
    instance.shutdown()
    assert process.poll() is not None


@pytest.mark.skipif(WINDOWS, reason="POSIX process check")
def test_worker_dies_with_host():
    script = textwrap.dedent(
        """
        import os, sys
        from dspy_interpreters import LocalInterpreter
        i = LocalInterpreter(mode="subprocess")
        i.start()
        # A guest-spawned child must not outlive the host either (process-group reaper).
        child = i.execute("import subprocess; subprocess.Popen(['sleep', '300']).pid")
        print(i._session.session_dir, flush=True)
        print(i._session.worker_pid, flush=True)
        print(child, flush=True)
        os._exit(0)
        """
    )
    output = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60, check=True
    ).stdout
    session_dir, pid_text, child_text = output.strip().splitlines()[-3:]
    pids = [int(pid_text), int(child_text)]
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and any(_process_alive(pid) for pid in pids):
            time.sleep(0.1)
        survivors = [pid for pid in pids if _process_alive(pid)]
        for pid in survivors:
            _kill_quietly(pid)
        assert not survivors, f"processes survived the death of their host: {survivors}"
    finally:
        _remove_session_dir(session_dir)  # the host died without shutdown(), so nobody else cleans it


def _remove_session_dir(path: str) -> None:
    if not os.path.isdir(path):
        return
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            with contextlib.suppress(OSError):
                os.chmod(os.path.join(root, name), 0o700)
    shutil.rmtree(path, ignore_errors=True)


def _process_alive(pid: int) -> bool:
    if LINUX:
        try:
            with open(f"/proc/{pid}/stat") as handle:
                state = handle.read().rsplit(")", 1)[1].split()[0]
        except OSError:
            return False
        return state != "Z"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# --------------------------------------------------------------------------- #
# Plain backend: resource caps and environment (routed explicitly)
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(WINDOWS, reason="rlimits are POSIX")
def test_clean_environment_and_rlimits(plain_only: None, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DSPY_HOST_SECRET_MARKER", "present")
    monkeypatch.setenv("DSPY_PASSTHROUGH_MARKER", "through")
    limits = ResourceLimits(cpu_seconds=30, max_processes=64, memory="512M" if LINUX else None)
    spec = IsolationSpec(
        limits=limits,
        env=EnvPolicy(mode="clean", passthrough=("DSPY_PASSTHROUGH_MARKER",), variables={"DSPY_EXPLICIT": "yes"}),
    )
    instance = subprocess_interpreter(isolation=spec)
    try:
        instance.start()
        report = instance.isolation_report
        assert report is not None and not report.missing
        assert report.guarantees[CLEAN_ENVIRONMENT]
        assert report.guarantees[CPU_TIME_CAPPED] == "RLIMIT_CPU"
        assert PROCESS_COUNT_CAPPED in report.guarantees
        env = instance.execute("import os; dict(os.environ)")
        assert "DSPY_HOST_SECRET_MARKER" not in env
        assert env["DSPY_PASSTHROUGH_MARKER"] == "through"
        assert env["DSPY_EXPLICIT"] == "yes"
        assert env["TMPDIR"] == os.path.join(instance._session.session_dir, "tmp")
        cpu = instance.execute("import resource; resource.getrlimit(resource.RLIMIT_CPU)")
        assert cpu[0] == 31
        nproc = instance.execute("import resource; resource.getrlimit(resource.RLIMIT_NPROC)")
        assert nproc[0] <= 64
        if LINUX:
            assert report.guarantees[MEMORY_CAPPED] == "RLIMIT_AS"
            address_space = instance.execute("import resource; resource.getrlimit(resource.RLIMIT_AS)")
            assert address_space[0] <= 512 * 1024**2
            with pytest.raises(CodeExecutionError, match="MemoryError"):
                instance.execute("blob = bytearray(600 * 1024 * 1024)")
            assert instance.execute("1 + 1") == 2
    finally:
        instance.shutdown()


def test_plain_backend_capability_tables():
    linux = PlainBackend(platform="linux").capabilities()
    assert linux.supported[KILLED_WITH_HOST] == "PR_SET_PDEATHSIG"
    assert linux.supported[MEMORY_CAPPED] == "RLIMIT_AS"
    assert FILESYSTEM_ALLOWLIST in linux.unsupported
    darwin = PlainBackend(platform="darwin").capabilities()
    assert darwin.supported[KILLED_WITH_HOST] == "ppid watchdog"
    assert MEMORY_CAPPED in darwin.unsupported
    assert darwin.supported[CPU_TIME_CAPPED] == "RLIMIT_CPU"
    windows = PlainBackend(platform="win32").capabilities()
    assert KILLED_WITH_HOST in windows.supported
    assert FILESYSTEM_ALLOWLIST in windows.unsupported
    for table in (linux, darwin, windows):
        assert "private_tmp" in table.unsupported
        assert table.unsupported["private_tmp"] == "plain backend has no filesystem policy"
        assert json.dumps(table.to_dict())


def test_plain_backend_plans(tmp_path):
    session_dir = str(tmp_path)
    worker = str(tmp_path / "worker.py")
    spec = IsolationSpec(limits=ResourceLimits(memory="64M", cpu_seconds=2, max_processes=8, wall_time_seconds=3))
    linux_plan = PlainBackend(platform="linux").plan(
        spec, python="python3", worker_path=worker, session_dir=session_dir
    )
    assert linux_plan.argv == ["python3", "-u", worker]
    assert linux_plan.policy["rlimits"] == {"core": 0, "cpu": 3, "nproc": 8, "as": 64 * 1024**2}
    assert set(linux_plan.required_applied) == {"pdeathsig", "rlimit:cpu", "rlimit:nproc", "rlimit:as"}
    assert linux_plan.popen_kwargs == {"start_new_session": True}
    assert linux_plan.cwd == os.path.join(session_dir, "work")
    assert linux_plan.report.guarantees[WALL_TIME_CAPPED]
    assert not linux_plan.report.missing
    with pytest.raises(IsolationUnsupportedError) as info:
        PlainBackend(platform="darwin").plan(spec, python="python3", worker_path=worker, session_dir=session_dir)
    assert set(info.value.unmet) == {MEMORY_CAPPED}
    darwin_plan = PlainBackend(platform="darwin").plan(
        IsolationSpec(limits=ResourceLimits(cpu_seconds=2), env=EnvPolicy(mode="clean")),
        python="python3",
        worker_path=worker,
        session_dir=session_dir,
    )
    assert darwin_plan.argv == ["python3", "-I", "-u", worker]
    assert "ppid_watchdog" in darwin_plan.required_applied
    assert "as" not in darwin_plan.policy["rlimits"]
    assert darwin_plan.env["TMPDIR"] == os.path.join(session_dir, "tmp")
    windows_plan = PlainBackend(platform="win32").plan(
        IsolationSpec(), python="python.exe", worker_path=worker, session_dir=session_dir
    )
    assert windows_plan.policy["rlimits"] == {}
    assert windows_plan.popen_kwargs["creationflags"] == 0x00000200 | 0x08000000
