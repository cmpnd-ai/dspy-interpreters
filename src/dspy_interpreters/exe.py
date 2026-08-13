from __future__ import annotations

import json
import queue
import re
import shlex
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from dspy import CodeInterpreterError

from dspy_interpreters.modal import _WORKER, ModalInterpreter


def _find_field(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        if name in value:
            return value[name]
        for child in value.values():
            found = _find_field(child, name)
            if found is not None:
                return found
    if isinstance(value, list):
        for child in value:
            found = _find_field(child, name)
            if found is not None:
                return found
    return None


class _Input:
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def write(self, value: str) -> None:
        self._stream.write(value)

    def drain(self) -> None:
        self._stream.flush()


_EOF = object()


class _TimedLines:
    def __init__(self, stream: Any, timeout: float) -> None:
        self._queue: queue.Queue[Any] = queue.Queue()
        self._timeout = timeout
        self._deadline: float | None = None
        threading.Thread(target=self._read, args=(stream,), daemon=True).start()

    def _read(self, stream: Any) -> None:
        try:
            for line in stream:
                self._queue.put(line)
        except Exception as exc:
            self._queue.put(exc)
        finally:
            self._queue.put(_EOF)

    def __iter__(self) -> _TimedLines:
        return self

    def set_deadline(self) -> None:
        self._deadline = time.monotonic() + self._timeout

    def clear_deadline(self) -> None:
        self._deadline = None

    def __next__(self) -> str:
        timeout = self._timeout
        if self._deadline is not None:
            timeout = max(0, min(timeout, self._deadline - time.monotonic()))
        try:
            item = self._queue.get(timeout=timeout)
        except queue.Empty as exc:
            raise TimeoutError(f"exe.dev execution exceeded {self._timeout:g}s") from exc
        if item is _EOF:
            raise StopIteration
        if isinstance(item, Exception):
            raise item
        return item


class _SSHProcessSandbox:
    def __init__(
        self,
        ssh_dest: str,
        ssh_options: Sequence[str],
        worker_path: str,
        command_timeout: float,
        execution_timeout: float,
    ) -> None:
        self._ssh_dest = ssh_dest
        self._ssh_options = list(ssh_options)
        self._worker_path = worker_path
        self._command_timeout = command_timeout
        upload_command = f"mkdir -p ~/.cache/dspy-interpreters && cat > {shlex.quote(worker_path)}"
        try:
            upload = subprocess.run(
                ["ssh", *ssh_options, ssh_dest, upload_command],
                input=_WORKER,
                text=True,
                capture_output=True,
                check=False,
                timeout=command_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"worker upload exceeded {command_timeout:g}s") from exc
        if upload.returncode != 0:
            raise RuntimeError(f"worker upload failed: {upload.stderr.strip()}")
        self.process = subprocess.Popen(
            ["ssh", *ssh_options, ssh_dest, f"python3 -u {shlex.quote(worker_path)}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        if self.process.stdin is None or self.process.stdout is None:
            self.process.kill()
            raise RuntimeError("ssh did not create protocol streams")
        self.stdin = _Input(self.process.stdin)
        self.stdout = _TimedLines(self.process.stdout, execution_timeout)
        if self.process.stderr is not None:
            threading.Thread(target=self._drain, args=(self.process.stderr,), daemon=True).start()

    @staticmethod
    def _drain(stream: Any) -> None:
        for _ in stream:
            pass

    def terminate(self, wait: bool = False) -> int | None:
        if self.process.poll() is None:
            self.process.terminate()
        if not wait:
            return None
        try:
            exit_code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            exit_code = self.process.wait(timeout=5)
        try:
            subprocess.run(
                ["ssh", *self._ssh_options, self._ssh_dest, f"rm -f {shlex.quote(self._worker_path)}"],
                text=True,
                capture_output=True,
                check=False,
                timeout=self._command_timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        return exit_code


def _validate_identifier(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("-")
        or not re.fullmatch(r"[A-Za-z0-9_.+@:-]+", value)
    ):
        raise CodeInterpreterError(f"exe.dev returned an invalid {label}: {value!r}")
    return value


def _vm_name_from_ssh_dest(ssh_dest: str) -> str | None:
    destination = ssh_dest.rsplit("@", 1)[-1]
    user = ssh_dest.rsplit("@", 1)[0] if "@" in ssh_dest else ""
    if user.startswith("vm+") and len(user) > 3:
        return user[3:]
    if destination.endswith(".exe.xyz") and destination != "exe.xyz":
        return destination.removesuffix(".exe.xyz")
    return None


class ExeDevInterpreter(ModalInterpreter):
    """Persistent remote CPython interpreter in an exe.dev VM.

    exe.dev exposes durable VMs over SSH rather than a Python sandbox SDK. This
    adapter provisions a VM when ``ssh_dest`` is omitted and carries the
    bidirectional host-tool protocol over SSH.
    """

    _provider_name = "exe.dev"

    def __init__(
        self,
        tools: Mapping[str, Callable[..., Any]] | None = None,
        output_fields: Sequence[Mapping[str, Any]] | None = None,
        *,
        ssh_dest: str | None = None,
        vm_name: str | None = None,
        create_args: Sequence[str] = (),
        ssh_options: Sequence[str] = (
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "StrictHostKeyChecking=accept-new",
        ),
        readiness_timeout: float = 120.0,
        command_timeout: float = 30.0,
        execution_timeout: float = 300.0,
        owns_vm: bool | None = None,
        process_factory: Callable[[], Any] | None = None,
    ) -> None:
        super().__init__(tools=tools, output_fields=output_fields, sandbox_factory=process_factory)
        self._ssh_dest = None if ssh_dest is None else _validate_identifier(ssh_dest, "ssh_dest")
        derived_name = _vm_name_from_ssh_dest(self._ssh_dest) if self._ssh_dest is not None else None
        cleanup_name = vm_name or derived_name
        self._vm_name = None if cleanup_name is None else _validate_identifier(cleanup_name, "vm_name")
        self._create_args = list(create_args)
        self._ssh_options = list(ssh_options)
        self._readiness_timeout = readiness_timeout
        self._command_timeout = command_timeout
        self._execution_timeout = execution_timeout
        self._owns_vm = ssh_dest is None if owns_vm is None else owns_vm
        self._worker_path = f".cache/dspy-interpreters/worker-{id(self)}.py"
        self._vm_removed = False

    @property
    def execution_instructions(self) -> str:
        return (
            "Code runs as CPython in a persistent remote exe.dev Linux VM. Variables, imports, functions, files, "
            "working-directory changes, and installed packages persist for this session. The VM provides normal "
            "Linux filesystem, process, package-installation, and network capabilities. Host tools execute outside "
            "the VM and their credentials are not copied into it."
        )

    def _control(self, *args: str) -> Any:
        try:
            result = subprocess.run(
                ["ssh", *self._ssh_options, "exe.dev", shlex.join([*args, "--json"])],
                text=True,
                capture_output=True,
                check=False,
                timeout=self._command_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise CodeInterpreterError(f"exe.dev {' '.join(args)} exceeded {self._command_timeout:g}s") from exc
        if result.returncode != 0:
            raise CodeInterpreterError(f"exe.dev {' '.join(args)} failed: {result.stderr.strip()}")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise CodeInterpreterError(f"exe.dev returned invalid JSON: {result.stdout!r}") from exc

    def _provision(self) -> None:
        response = self._control("new", *self._create_args)
        ssh_dest = _find_field(response, "ssh_dest")
        vm_name = _find_field(response, "vm_name") or _find_field(response, "name")
        derived_name = _vm_name_from_ssh_dest(ssh_dest) if isinstance(ssh_dest, str) else None
        self._vm_name = _validate_identifier(vm_name or derived_name, "vm_name")
        self._ssh_dest = _validate_identifier(ssh_dest, "ssh_dest")

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self._readiness_timeout
        last_error = ""
        while time.monotonic() < deadline:
            try:
                result = subprocess.run(
                    ["ssh", *self._ssh_options, self._ssh_dest, "python3 -V"],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=self._command_timeout,
                )
            except subprocess.TimeoutExpired:
                last_error = f"readiness probe exceeded {self._command_timeout:g}s"
                continue
            if result.returncode == 0:
                return
            last_error = result.stderr.strip()
            time.sleep(2)
        raise CodeInterpreterError(f"exe.dev VM did not become SSH/Python ready: {last_error}")

    def start(self) -> None:
        self._check_active()
        if self._sandbox is not None:
            return
        if self._sandbox_factory is None:
            try:
                if self._ssh_dest is None:
                    self._provision()
                self._wait_until_ready()
                self._sandbox_factory = lambda: _SSHProcessSandbox(
                    self._ssh_dest,
                    self._ssh_options,
                    self._worker_path,
                    self._command_timeout,
                    self._execution_timeout,
                )
            except Exception:
                self._remove_owned_vm(warn=True)
                raise
        try:
            super().start()
        except Exception:
            self._remove_owned_vm(warn=True)
            raise

    def _remove_owned_vm(self, *, warn: bool) -> None:
        if not self._owns_vm or not self._vm_name or self._vm_removed:
            return
        try:
            self._control("rm", self._vm_name)
        except Exception as exc:
            if warn:
                print(f"warning: unable to remove exe.dev VM {self._vm_name}: {exc}", file=sys.stderr)
        else:
            self._vm_removed = True

    def shutdown(self) -> None:
        shutdown_error: BaseException | None = None
        try:
            super().shutdown()
        except BaseException as exc:
            shutdown_error = exc
        finally:
            self._remove_owned_vm(warn=True)
        if shutdown_error is not None:
            raise shutdown_error


__all__ = ["ExeDevInterpreter"]
