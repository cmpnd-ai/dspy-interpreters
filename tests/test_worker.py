"""Tests for the subprocess worker script (``dspy_interpreters/isolation/_worker.py``)."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import Any

import pytest

import dspy_interpreters.isolation._worker as worker_module

WORKER_PATH = os.path.abspath(worker_module.__file__)
LINUX = sys.platform.startswith("linux")
TIMEOUT = 30.0


def base_policy(**overrides: Any) -> dict[str, Any]:
    policy: dict[str, Any] = {
        "type": "policy",
        "version": 1,
        "die_with_parent": True,
        "chdir": None,
        "rlimits": {"core": 0},
        "landlock": None,
        "unshare_net": None,
        "no_new_privs": None,
        "seccomp": None,
    }
    policy.update(overrides)
    return policy


class Worker:
    """Drive one worker process over its JSON-lines protocol."""

    def __init__(self, policy: dict[str, Any] | None = None, *, send_policy: bool = True, **popen_kwargs: Any) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-I", "-u", WORKER_PATH],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **popen_kwargs,
        )
        self._lines: queue.Queue[bytes | None] = queue.Queue()
        self._stderr = bytearray()
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        self.ready: dict[str, Any] | None = None
        if send_policy:
            self.send(policy or base_policy())
            self.ready = self.recv()

    def _pump(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def _drain_stderr(self) -> None:
        assert self.process.stderr is not None
        for chunk in iter(lambda: self.process.stderr.read(4096), b""):
            self._stderr.extend(chunk)

    def send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write((json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8"))
        self.process.stdin.flush()

    def recv(self) -> dict[str, Any]:
        line = self._lines.get(timeout=TIMEOUT)
        if line is None:
            raise EOFError(f"worker closed its stdout; stderr={self.stderr!r}")
        message = json.loads(line)
        assert isinstance(message, dict)
        return message

    def execute(
        self,
        code: str,
        *,
        variables: dict[str, Any] | None = None,
        tools: list[str] | None = None,
        output_fields: list[dict[str, Any]] | None = None,
        handler: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        self.send(
            {
                "type": "execute",
                "code": code,
                "variables": variables or {},
                "tools": tools or [],
                "output_fields": output_fields,
            }
        )
        while True:
            message = self.recv()
            if message.get("type") == "tool_request":
                assert handler is not None, f"unexpected tool_request {message!r}"
                self.send(handler(message))
                continue
            return message

    def value(self, code: str, **kwargs: Any) -> Any:
        message = self.execute(code, **kwargs)
        assert message == {**message, "type": "execution_result", "kind": "result"}, message
        return message["value"]

    @property
    def stderr(self) -> str:
        return bytes(self._stderr).decode("utf-8", "replace")

    def wait(self) -> int:
        try:
            return self.process.wait(timeout=TIMEOUT)
        finally:
            self.close()

    def close(self) -> None:
        for stream in (self.process.stdin,):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=TIMEOUT)

    def applied(self, name: str) -> bool:
        assert self.ready is not None
        return any(item == name or item.startswith(name + ":") for item in self.ready["applied"])

    def skip_unless_applied(self, name: str) -> None:
        if not self.applied(name):
            assert self.ready is not None
            reason = self.ready["skipped"].get(name, "not attempted")
            self.close()
            pytest.skip(f"{name} not applied in this environment: {reason}")


@pytest.fixture
def worker():
    instance = Worker()
    try:
        yield instance
    finally:
        instance.close()


# --------------------------------------------------------------------------- #
# Handshake
# --------------------------------------------------------------------------- #


def test_ready_message_shape(worker: Worker):
    ready = worker.ready
    assert ready is not None
    assert ready["type"] == "ready"
    assert ready["pid"] == worker.process.pid
    assert isinstance(ready["applied"], list)
    assert isinstance(ready["skipped"], dict)
    assert "umask" in ready["applied"]
    assert "rlimit:core" in ready["applied"] or "rlimit:core" in ready["skipped"]
    assert worker.applied("pdeathsig") or worker.applied("ppid_watchdog")


def test_first_message_must_be_policy():
    instance = Worker(send_policy=False)
    try:
        instance.send({"type": "execute", "code": "1", "variables": {}, "tools": [], "output_fields": None})
        message = instance.recv()
        assert message["type"] == "terminal_error"
        assert "policy" in message["error"]
        assert instance.wait() == 2
    finally:
        instance.close()


def test_unknown_message_is_terminal(worker: Worker):
    worker.send({"type": "bogus"})
    message = worker.recv()
    assert message["type"] == "terminal_error"
    assert "unknown host protocol message" in message["error"]
    assert worker.wait() != 0


def test_shutdown_exits_zero(worker: Worker):
    assert worker.value("1 + 1") == 2
    worker.send({"type": "shutdown"})
    assert worker.wait() == 0


def test_eof_exits_zero(worker: Worker):
    assert worker.process.stdin is not None
    worker.process.stdin.close()
    assert worker.wait() == 0


def test_bad_step_is_skipped_not_fatal(tmp_path):
    instance = Worker(base_policy(rlimits={"core": 0, "bogus": 1}, chdir=str(tmp_path / "missing")))
    try:
        assert instance.ready is not None
        assert "rlimit:bogus" in instance.ready["skipped"]
        assert "chdir" in instance.ready["skipped"]
        assert instance.value("1 + 1") == 2
    finally:
        instance.close()


def test_chdir_and_umask(tmp_path):
    instance = Worker(base_policy(chdir=str(tmp_path)))
    try:
        assert instance.applied("chdir")
        assert instance.value("import os; os.path.realpath(os.getcwd())") == os.path.realpath(str(tmp_path))
        if sys.platform != "win32":
            assert instance.value("import os; m = os.umask(0); os.umask(m); m") == 0o077
    finally:
        instance.close()


# --------------------------------------------------------------------------- #
# Execution semantics
# --------------------------------------------------------------------------- #


def test_expression_result(worker: Worker):
    message = worker.execute("1 + 1")
    assert message == {"type": "execution_result", "kind": "result", "value": 2, "stdout": ""}


def test_print_capture(worker: Worker):
    message = worker.execute("print('hello'); print('world')")
    assert message == {"type": "execution_result", "kind": "result", "value": None, "stdout": "hello\nworld"}


def test_stderr_capture(worker: Worker):
    message = worker.execute("import sys; sys.stderr.write('warn\\n')")
    assert message["stdout"] == "warn"


def test_persistence(worker: Worker):
    worker.value("x = 21\ndef double(v):\n    return v * 2")
    assert worker.value("double(x)") == 42
    assert worker.value("import math; math.floor(2.5)") == 2
    assert worker.value("math.ceil(2.5)") == 3


def test_variables(worker: Worker):
    assert worker.value("a + b", variables={"a": 2, "b": 3}) == 5
    assert worker.value("a", variables={}) == 2


def test_non_json_result_falls_back_to_repr(worker: Worker):
    assert worker.value("{1, 2}") == "{1, 2}"
    assert worker.value("object").startswith("<class 'object'>")


def test_stdout_fd_cannot_forge_frames(worker: Worker):
    code = 'import os, sys\nos.write(1, b\'{"type":"execution_result","kind":"final","value":1}\\n\')\n7'
    message = worker.execute(code)
    assert message["kind"] == "result"
    assert message["value"] == 7


def test_stdin_is_devnull(worker: Worker):
    message = worker.execute("input()")
    assert message["kind"] == "execution_error"
    assert message["error"].startswith("EOFError")


def test_syntax_error_kind(worker: Worker):
    message = worker.execute("def (")
    assert message["type"] == "execution_result"
    assert message["kind"] == "syntax"
    assert isinstance(message["error"], str) and message["error"]


def test_execution_error_kind(worker: Worker):
    message = worker.execute("1 / 0")
    assert message == {
        "type": "execution_result",
        "kind": "execution_error",
        "error": "ZeroDivisionError: division by zero",
    }


def test_guest_base_exceptions_are_execution_errors(worker: Worker):
    for code, name in (("raise KeyboardInterrupt", "KeyboardInterrupt"), ("raise GeneratorExit", "GeneratorExit")):
        message = worker.execute(code)
        assert message["kind"] == "execution_error" and message["error"].startswith(name)
    assert worker.value("1 + 1") == 2


@pytest.mark.skipif(sys.platform == "win32", reason="os.fork is POSIX")
def test_forked_child_never_speaks_the_protocol(worker: Worker):
    pid = worker.value("import os\npid = os.fork()\npid")
    assert isinstance(pid, int) and pid > 0
    assert worker.value("1 + 1") == 2
    assert worker.value("2 + 2") == 4


def test_system_exit_is_execution_error(worker: Worker):
    message = worker.execute("exit()")
    assert message["kind"] == "execution_error"
    assert message["error"].startswith("SystemExit")
    message = worker.execute("raise SystemExit(3)")
    assert message["error"] == "SystemExit: 3"
    assert worker.value("'alive'") == "alive"


# --------------------------------------------------------------------------- #
# Tools and SUBMIT
# --------------------------------------------------------------------------- #


def test_tool_round_trip(worker: Worker):
    seen: list[dict[str, Any]] = []

    def handler(request: dict[str, Any]) -> dict[str, Any]:
        seen.append(request)
        assert request["type"] == "tool_request"
        assert request["name"] == "add"
        return {"type": "tool_response", "id": request["id"], "ok": True, "value": sum(request["args"])}

    assert worker.value("add(2, 3) + add(1, 1)", tools=["add"], handler=handler) == 7
    assert [request["args"] for request in seen] == [[2, 3], [1, 1]]
    assert all(isinstance(request["id"], str) and request["id"] for request in seen)
    assert seen[0]["kwargs"] == {}


def test_tool_kwargs_and_error(worker: Worker):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        if request["kwargs"].get("fail"):
            return {"type": "tool_response", "id": request["id"], "ok": False, "error": "RuntimeError: boom"}
        return {"type": "tool_response", "id": request["id"], "ok": True, "value": request["kwargs"]}

    assert worker.value("echo(a=1)", tools=["echo"], handler=handler) == {"a": 1}
    message = worker.execute("echo(fail=True)", tools=["echo"], handler=handler)
    assert message["kind"] == "execution_error"
    assert message["error"] == "HostToolError: RuntimeError: boom"
    # Guest code can catch tool errors and continue.
    code = "try:\n    echo(fail=True)\nexcept Exception as e:\n    r = type(e).__name__\nr"
    assert worker.value(code, tools=["echo"], handler=handler) == "HostToolError"


def test_tool_revocation_on_rebind(worker: Worker):
    def handler(request: dict[str, Any]) -> dict[str, Any]:
        return {"type": "tool_response", "id": request["id"], "ok": True, "value": 1}

    assert worker.value("add(1)", tools=["add"], handler=handler) == 1
    message = worker.execute("add(1)", tools=[])
    assert message["kind"] == "execution_error"
    assert message["error"].startswith("NameError")
    # A stale reference kept by the guest still calls a host tool only if the host answers.
    assert worker.value("saved = add; 1", tools=["add"], handler=handler) == 1
    assert worker.value("'add' in dir()", tools=[]) is False


def test_invalid_tool_name_is_terminal(worker: Worker):
    message = worker.execute("1", tools=["SUBMIT"])
    assert message["type"] == "terminal_error"
    assert "invalid tool name" in message["error"]
    assert worker.wait() != 0


def test_submit_untyped(worker: Worker):
    message = worker.execute("SUBMIT(42)")
    assert message == {"type": "execution_result", "kind": "final", "value": {"output": 42}}
    message = worker.execute("SUBMIT(1, 2)")
    assert message["kind"] == "execution_error"
    assert message["error"].startswith("TypeError")


def test_submit_typed(worker: Worker):
    fields = [{"name": "answer", "type": "int"}, {"name": "reason", "type": "str"}]
    message = worker.execute("SUBMIT(answer=1, reason='x')", output_fields=fields)
    assert message == {"type": "execution_result", "kind": "final", "value": {"answer": 1, "reason": "x"}}
    message = worker.execute("SUBMIT(2, 'y')", output_fields=fields)
    assert message["value"] == {"answer": 2, "reason": "y"}
    message = worker.execute("SUBMIT(answer=1)", output_fields=fields)
    assert message["kind"] == "execution_error"
    assert message["error"].startswith("TypeError")
    message = worker.execute("SUBMIT(1, reason='y')", output_fields=fields)
    assert message["kind"] == "execution_error"


def test_submit_non_json_value_keeps_structure(worker: Worker):
    message = worker.execute("SUBMIT(object)")
    assert message["kind"] == "final"
    assert isinstance(message["value"]["output"], str)


def test_submit_inside_function_and_after_output(worker: Worker):
    code = "def f():\n    print('before')\n    SUBMIT('done')\nf()"
    message = worker.execute(code)
    assert message == {"type": "execution_result", "kind": "final", "value": {"output": "done"}}


# --------------------------------------------------------------------------- #
# Static checks on the module (any OS)
# --------------------------------------------------------------------------- #


def test_module_imports_without_side_effects():
    assert callable(worker_module.main)
    assert set(worker_module.DENIED_SYSCALLS) == {"x86_64", "aarch64"}
    for name in ("ptrace", "mount", "unshare", "bpf", "keyctl", "io_uring_setup", "setns"):
        for arch in ("x86_64", "aarch64"):
            assert name in worker_module.DENIED_SYSCALLS[arch], (name, arch)
    assert worker_module.DENIED_SYSCALLS["x86_64"]["ptrace"] == 101
    assert worker_module.DENIED_SYSCALLS["aarch64"]["ptrace"] == 117
    assert "mknod" not in worker_module.DENIED_SYSCALLS["aarch64"]
    assert "ioperm" not in worker_module.DENIED_SYSCALLS["aarch64"]
    assert "clone" not in worker_module.DENIED_SYSCALLS["x86_64"]
    assert "clone3" not in worker_module.DENIED_SYSCALLS["x86_64"]


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
def test_seccomp_program_is_well_formed(machine: str):
    program = worker_module.build_seccomp_program(machine)
    assert 0 < len(program) < 4096
    assert program[0] == (worker_module.BPF_LD_W_ABS, 0, 0, 4)
    assert program[1] == (worker_module.BPF_JMP_JEQ_K, 1, 0, worker_module.AUDIT_ARCH[machine])
    assert program[2] == (worker_module.BPF_RET_K, 0, 0, worker_module.SECCOMP_RET_KILL_PROCESS)
    assert program[-1] == (worker_module.BPF_RET_K, 0, 0, worker_module.SECCOMP_RET_ALLOW)
    for index, (code, jt, jf, _k) in enumerate(program):
        if code in (worker_module.BPF_JMP_JEQ_K, worker_module.BPF_JMP_JGE_K, worker_module.BPF_JMP_JSET_K):
            assert index + 1 + jt < len(program)
            assert index + 1 + jf < len(program)
    denied = {k for code, _jt, _jf, k in program if code == worker_module.BPF_JMP_JEQ_K}
    assert set(worker_module.DENIED_SYSCALLS[machine].values()) <= denied
    assert worker_module.CLONE3_NR in denied
    assert worker_module.CLONE_NR[machine] in denied
    has_x32_check = any(code == worker_module.BPF_JMP_JGE_K for code, *_ in program)
    assert has_x32_check == (machine == "x86_64")
    assert worker_module.SOCKET_NR[machine] not in denied  # AF_UNIX rule is opt-in


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
def test_seccomp_program_unix_socket_rule(machine: str):
    program = worker_module.build_seccomp_program(machine, deny_unix_sockets=True)
    base = worker_module.build_seccomp_program(machine)
    assert len(program) == len(base) + 5
    assert program[-1] == (worker_module.BPF_RET_K, 0, 0, worker_module.SECCOMP_RET_ALLOW)
    tail = program[-6:-1]
    assert tail[0] == (worker_module.BPF_LD_W_ABS, 0, 0, 0)  # reload nr
    assert tail[1] == (worker_module.BPF_JMP_JEQ_K, 0, 3, worker_module.SOCKET_NR[machine])
    assert tail[2] == (worker_module.BPF_LD_W_ABS, 0, 0, 16)  # arg0 = domain
    assert tail[3] == (worker_module.BPF_JMP_JEQ_K, 0, 1, worker_module.AF_UNIX)
    assert tail[4] == (worker_module.BPF_RET_K, 0, 0, worker_module.SECCOMP_RET_ERRNO | worker_module.EPERM)
    for index, (code, jt, jf, _k) in enumerate(program):
        if code in (worker_module.BPF_JMP_JEQ_K, worker_module.BPF_JMP_JGE_K, worker_module.BPF_JMP_JSET_K):
            assert index + 1 + jt < len(program)
            assert index + 1 + jf < len(program)


def test_seccomp_program_rejects_unknown_machine():
    with pytest.raises(RuntimeError):
        worker_module.build_seccomp_program("mips")


def test_worker_runs_as_plain_script_without_isolated_flag():
    process = subprocess.Popen(
        [sys.executable, WORKER_PATH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        out, err = process.communicate(
            (json.dumps(base_policy()) + "\n" + json.dumps({"type": "shutdown"}) + "\n").encode("utf-8"),
            timeout=TIMEOUT,
        )
    finally:
        if process.poll() is None:
            process.kill()
    assert process.returncode == 0, err
    ready = json.loads(out.splitlines()[0])
    assert ready["type"] == "ready"


# --------------------------------------------------------------------------- #
# Linux ratchet
# --------------------------------------------------------------------------- #

linux_only = pytest.mark.skipif(not LINUX, reason="Linux-only confinement mechanism")


def _guarded(statement: str) -> str:
    """Guest code that evaluates to the exception type name of ``statement`` or ``'ok'``."""
    return f"try:\n    {statement}\n    r = 'ok'\nexcept Exception as e:\n    r = type(e).__name__\nr"


@linux_only
def test_landlock_blocks_paths_outside_allowlist(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("secret")
    policy = base_policy(
        chdir=str(work),
        landlock={
            "required": True,
            "read": [sys.prefix, sys.base_prefix, "/usr", "/lib", "/lib64", "/etc"],
            "write": [str(work)],
            "rw_files": ["/dev/null", "/dev/urandom"],
        },
    )
    instance = Worker(policy)
    try:
        instance.skip_unless_applied("landlock")
        assert any(item.startswith("landlock:abi") for item in instance.ready["applied"])
        code = _guarded(f"open({str(secret)!r}).read()")
        assert instance.value(code) == "PermissionError"
        assert instance.value("open('marker.txt', 'w').write('x'); open('marker.txt').read()") == "x"
        assert (work / "marker.txt").read_text() == "x"
        assert instance.value("import os; len(os.urandom(4))") == 4
        assert instance.value("import json, socket; 'ok'") == "ok"
        assert instance.value("open('/dev/null', 'w').write('x')") == 1
        code = _guarded(f"open({str(outside / 'new.txt')!r}, 'w')")
        assert instance.value(code) == "PermissionError"
    finally:
        instance.close()


@linux_only
def test_unshare_net_removes_network():
    instance = Worker(base_policy(unshare_net={"required": True}))
    try:
        instance.skip_unless_applied("unshare_net")
        code = (
            "import socket\n"
            "s = socket.socket()\n"
            "s.settimeout(5)\n"
            "try:\n"
            "    s.connect(('127.0.0.1', 9))\n"
            "    r = 'connected'\n"
            "except OSError as e:\n"
            "    r = e.errno\n"
            "s.close()\n"
            "r"
        )
        import errno

        assert instance.value(code) == errno.ENETUNREACH
        assert instance.value("import socket; [name for _i, name in socket.if_nameindex()]") == ["lo"]
    finally:
        instance.close()


@linux_only
def test_no_new_privs_flag():
    instance = Worker(base_policy(no_new_privs={"required": True}))
    try:
        instance.skip_unless_applied("no_new_privs")
        status = instance.value("open('/proc/self/status').read()")
        assert "NoNewPrivs:\t1" in status
    finally:
        instance.close()


@linux_only
def test_seccomp_denylist():
    instance = Worker(base_policy(seccomp={"required": True}))
    try:
        instance.skip_unless_applied("seccomp")
        assert instance.applied("no_new_privs") or "no_new_privs" not in instance.ready["skipped"]
        code = (
            "import ctypes, errno, os, subprocess, sys\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "r_unshare = libc.unshare(0x40000000)\n"
            "e_unshare = ctypes.get_errno()\n"
            "libc.ptrace.restype = ctypes.c_long\n"
            "r_ptrace = libc.ptrace(0, 0, 0, 0)\n"
            "e_ptrace = ctypes.get_errno()\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os._exit(7)\n"
            "_, status = os.waitpid(pid, 0)\n"
            "out = subprocess.run([sys.executable, '-c', 'print(6 * 7)'], capture_output=True, text=True).stdout\n"
            "import threading\n"
            "box = []\n"
            "t = threading.Thread(target=lambda: box.append('thread'))\n"
            "t.start(); t.join()\n"
            "[r_unshare, e_unshare, r_ptrace, e_ptrace, os.waitstatus_to_exitcode(status), out.strip(), box]"
        )
        result = instance.value(code)
        assert result == [-1, 1, -1, 1, 7, "42", ["thread"]], result
        assert instance.value("open('/proc/self/status').read()").count("Seccomp:\t2") == 1
    finally:
        instance.close()


@linux_only
def test_seccomp_denies_unix_sockets_when_asked():
    instance = Worker(base_policy(seccomp={"required": True, "deny_unix_sockets": True}))
    try:
        instance.skip_unless_applied("seccomp")
        code = (
            "import socket, asyncio, subprocess, sys\n"
            "results = {}\n"
            "for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):\n"
            "    try:\n"
            "        socket.socket(socket.AF_UNIX, kind).close()\n"
            "        results[str(int(kind))] = 'ok'\n"
            "    except OSError as exc:\n"
            "        results[str(int(kind))] = exc.errno\n"
            "a, b = socket.socketpair(); a.sendall(b'x'); results['pair'] = b.recv(1).decode(); a.close(); b.close()\n"
            "results['inet'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM).family.name\n"
            "results['asyncio'] = asyncio.run(asyncio.sleep(0, result=1))\n"
            "results['sub'] = subprocess.run([sys.executable, '-c', 'print(2)'], capture_output=True).stdout.decode()\n"
            "results"
        )
        results = instance.value(code)
        assert results == {"1": 1, "2": 1, "pair": "x", "inet": "AF_INET", "asyncio": 1, "sub": "2\n"}, results
        # Without the flag AF_UNIX sockets work.
        instance.close()
        plain = Worker(base_policy(seccomp={"required": True, "deny_unix_sockets": False}))
        try:
            plain.skip_unless_applied("seccomp")
            assert plain.value("import socket; socket.socket(socket.AF_UNIX).family.name") == "AF_UNIX"
        finally:
            plain.close()
    finally:
        instance.close()


@pytest.mark.skipif(sys.platform == "win32", reason="process groups are POSIX")
def test_pgroup_reaper_kills_guest_children_when_the_worker_dies():
    import signal
    import time

    # Without a session of its own the worker refuses the reaper (it would kill the caller's group).
    shared = Worker(base_policy(pgroup_reaper=True))
    try:
        assert "pgroup_reaper" in shared.ready["skipped"]
        assert "session" in shared.ready["skipped"]["pgroup_reaper"]
    finally:
        shared.close()
    instance = Worker(base_policy(pgroup_reaper=True), start_new_session=True)
    try:
        if not instance.applied("pgroup_reaper"):
            pytest.skip(f"pgroup_reaper not applied: {instance.ready['skipped'].get('pgroup_reaper')}")
        child = instance.value("import subprocess; subprocess.Popen(['sleep', '300']).pid")
        os.kill(instance.process.pid, signal.SIGKILL)  # abrupt worker death, no shutdown message
        deadline = time.monotonic() + 5.0
        alive = True
        while time.monotonic() < deadline and alive:
            try:
                os.kill(child, 0)
                alive = not _is_zombie(child)
            except ProcessLookupError:
                alive = False
            time.sleep(0.1)
        if alive:
            os.kill(child, signal.SIGKILL)
        assert not alive, "guest child survived the worker"
    finally:
        instance.close()


def _is_zombie(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        return False


@linux_only
def test_rlimit_as_caps_memory():
    instance = Worker(base_policy(rlimits={"core": 0, "as": 256 * 1024 * 1024}))
    try:
        instance.skip_unless_applied("rlimit:as")
        code = (
            "try:\n"
            "    blob = bytearray(300 * 1024 * 1024)\n"
            "    r = 'allocated'\n"
            "except MemoryError:\n"
            "    r = 'MemoryError'\n"
            "r"
        )
        assert instance.value(code) == "MemoryError"
        assert instance.value("'alive'") == "alive"
    finally:
        instance.close()


@linux_only
def test_full_ratchet_together(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("secret")
    policy = base_policy(
        chdir=str(work),
        rlimits={"core": 0, "cpu": 60, "nofile": 256},
        landlock={
            "required": True,
            "read": [sys.prefix, sys.base_prefix, "/usr", "/lib", "/lib64", "/etc"],
            "write": [str(work)],
            "rw_files": ["/dev/null", "/dev/urandom", "/dev/zero", "/dev/random"],
        },
        unshare_net={"required": True},
        no_new_privs={"required": True},
        seccomp={"required": True},
    )
    instance = Worker(policy)
    try:
        for name in ("landlock", "unshare_net", "no_new_privs", "seccomp"):
            instance.skip_unless_applied(name)
        assert instance.applied("pdeathsig")
        assert instance.value("import os; os.getcwd()") == os.path.realpath(str(work))
        assert instance.value("open('a.txt', 'w').write('hi')") == 2
        code = "import subprocess, sys; subprocess.run([sys.executable, '-c', 'print(1)'], capture_output=True).stdout"
        assert instance.value(code) == "b'1\\n'"
        message = instance.execute(f"open({str(secret)!r}).read()")
        assert message["kind"] == "execution_error"
        assert message["error"].startswith("PermissionError")
        # The uid/gid mapping of the new user namespace survives Landlock (worker allows the map files).
        assert instance.value("import os; [os.getuid(), os.getgid()]") == [os.getuid(), os.getgid()]
        assert instance.value("import socket; [name for _i, name in socket.if_nameindex()]") == ["lo"]
        instance.send({"type": "shutdown"})
        assert instance.wait() == 0
    finally:
        instance.close()
