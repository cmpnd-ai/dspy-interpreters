from __future__ import annotations

import json
import subprocess
import sys
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


class _SSHProcessSandbox:
    def __init__(self, ssh_dest: str, ssh_options: Sequence[str], worker_path: str) -> None:
        upload = subprocess.run(
            ["ssh", *ssh_options, ssh_dest, "mkdir -p ~/.cache/dspy-interpreters && cat > " + worker_path],
            input=_WORKER,
            text=True,
            capture_output=True,
            check=False,
        )
        if upload.returncode != 0:
            raise RuntimeError(f"worker upload failed: {upload.stderr.strip()}")
        self.process = subprocess.Popen(
            ["ssh", *ssh_options, ssh_dest, f"python3 -u {worker_path}"],
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
        self.stdout = self.process.stdout

    def terminate(self, wait: bool = False) -> int | None:
        if self.process.poll() is None:
            self.process.terminate()
        return self.process.wait(timeout=10) if wait else None


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
        ssh_options: Sequence[str] = ("-o", "BatchMode=yes", "-o", "ConnectTimeout=15"),
        readiness_timeout: float = 120.0,
        owns_vm: bool | None = None,
        process_factory: Callable[[], Any] | None = None,
    ) -> None:
        super().__init__(tools=tools, output_fields=output_fields, sandbox_factory=process_factory)
        self._ssh_dest = ssh_dest
        self._vm_name = vm_name
        self._create_args = list(create_args)
        self._ssh_options = list(ssh_options)
        self._readiness_timeout = readiness_timeout
        self._owns_vm = ssh_dest is None if owns_vm is None else owns_vm
        self._worker_path = f"~/.cache/dspy-interpreters/worker-{id(self)}.py"

    @property
    def execution_instructions(self) -> str:
        return (
            "Code runs as CPython in a persistent remote exe.dev Linux VM. Variables, imports, functions, files, "
            "working-directory changes, and installed packages persist for this session. The VM provides normal "
            "Linux filesystem, process, package-installation, and network capabilities. Host tools execute outside "
            "the VM and their credentials are not copied into it."
        )

    def _control(self, *args: str) -> Any:
        result = subprocess.run(
            ["ssh", *self._ssh_options, "exe.dev", *args, "--json"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise CodeInterpreterError(f"exe.dev {' '.join(args)} failed: {result.stderr.strip()}")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise CodeInterpreterError(f"exe.dev returned invalid JSON: {result.stdout!r}") from exc

    def _provision(self) -> None:
        response = self._control("new", *self._create_args)
        self._ssh_dest = _find_field(response, "ssh_dest")
        self._vm_name = _find_field(response, "vm_name") or _find_field(response, "name")
        if not isinstance(self._ssh_dest, str) or not self._ssh_dest:
            raise CodeInterpreterError(f"exe.dev new response omitted ssh_dest: {response!r}")
        if not isinstance(self._vm_name, str) or not self._vm_name:
            raise CodeInterpreterError(f"exe.dev new response omitted vm_name: {response!r}")

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self._readiness_timeout
        last_error = ""
        while time.monotonic() < deadline:
            result = subprocess.run(
                ["ssh", *self._ssh_options, self._ssh_dest, "python3 -V"],
                text=True,
                capture_output=True,
                check=False,
            )
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
                    self._ssh_dest, self._ssh_options, self._worker_path
                )
            except Exception:
                if self._owns_vm and self._vm_name:
                    try:
                        self._control("rm", self._vm_name)
                    except Exception:
                        pass
                raise
        try:
            super().start()
        except Exception:
            if self._owns_vm and self._vm_name:
                try:
                    self._control("rm", self._vm_name)
                except Exception:
                    pass
            raise

    def shutdown(self) -> None:
        already_ended = self._ended
        super().shutdown()
        if already_ended or not self._owns_vm or not self._vm_name:
            return
        try:
            self._control("rm", self._vm_name)
        except Exception as exc:
            print(f"warning: unable to remove exe.dev VM {self._vm_name}: {exc}", file=sys.stderr)


__all__ = ["ExeDevInterpreter"]
