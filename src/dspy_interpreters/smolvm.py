from __future__ import annotations

import subprocess
import sys
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from dspy import CodeInterpreterError

from dspy_interpreters.exe import _Input, _TimedLines
from dspy_interpreters.modal import _WORKER, ModalInterpreter


class _WorkerProcess:
    def __init__(self, command: Sequence[str], execution_timeout: float) -> None:
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        if self.process.stdin is None or self.process.stdout is None:
            self.process.kill()
            raise RuntimeError("smolvm exec did not create protocol streams")
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
            return self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            return self.process.wait(timeout=5)


class SmolvmInterpreter(ModalInterpreter):
    """Persistent CPython in a local smolvm microVM, one machine per session.

    Each session creates and boots a machine with its own Linux kernel, carries the
    host-tool protocol over ``smolvm machine exec``, and deletes the machine on
    shutdown. The machine has no network and no host directories unless
    ``create_args`` grant them.
    """

    _provider_name = "smolvm"

    execution_instructions = (
        "Code runs as CPython in a persistent local smolvm Linux microVM. Variables, imports, functions, and files "
        "persist for this session. The VM has no network access and no host files unless the host configured "
        "them, so only packages already installed in the VM image can be imported. Host tools execute outside "
        "the VM and their credentials are not copied into it."
    )

    def __init__(
        self,
        tools: Mapping[str, Callable[..., Any]] | None = None,
        output_fields: Sequence[Mapping[str, Any]] | None = None,
        *,
        image: str = "python:3.12-slim",
        pack: str | None = None,
        cpus: int = 1,
        memory: int = 1024,
        create_args: Sequence[str] = (),
        smolvm: str = "smolvm",
        command_timeout: float = 120.0,
        execution_timeout: float = 300.0,
        process_factory: Callable[[], Any] | None = None,
    ) -> None:
        super().__init__(tools=tools, output_fields=output_fields, sandbox_factory=process_factory)
        self._source = ["--from", pack] if pack else ["--image", image]
        self._cpus = cpus
        self._memory = memory
        self._create_args = list(create_args)
        self._smolvm = smolvm
        self._command_timeout = command_timeout
        self._execution_timeout = execution_timeout
        self._machine = f"dspy-{uuid.uuid4().hex[:12]}"
        self._machine_created = False

    def _cli(self, *args: str) -> None:
        try:
            result = subprocess.run(
                [self._smolvm, *args],
                text=True,
                capture_output=True,
                check=False,
                timeout=self._command_timeout,
            )
        except FileNotFoundError as exc:
            raise CodeInterpreterError(
                f"smolvm CLI not found at {self._smolvm!r}: install it from "
                "https://github.com/smol-machines/smolvm or pass smolvm=<path>"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise CodeInterpreterError(f"smolvm {' '.join(args[:2])} exceeded {self._command_timeout:g}s") from exc
        if result.returncode != 0:
            raise CodeInterpreterError(f"smolvm {' '.join(args[:2])} failed: {result.stderr.strip()}")

    def start(self) -> None:
        self._check_active()
        if self._sandbox is not None:
            return
        try:
            if self._sandbox_factory is None:
                create = ["machine", "create", "--name", self._machine, *self._source]
                self._cli(*create, "--cpus", str(self._cpus), "--mem", str(self._memory), *self._create_args)
                self._machine_created = True
                self._cli("machine", "start", "--name", self._machine)
                exec_ = [self._smolvm, "machine", "exec", "--name", self._machine, "-i", "--", "python3", "-u", "-c"]
                self._sandbox_factory = lambda: _WorkerProcess([*exec_, _WORKER], self._execution_timeout)
            super().start()
        except Exception:
            self._remove_machine()
            raise

    def _remove_machine(self) -> None:
        if not self._machine_created:
            return
        try:
            self._cli("machine", "delete", "--name", self._machine, "--force")
        except Exception as exc:
            print(f"warning: unable to remove smolvm machine {self._machine}: {exc}", file=sys.stderr)
        else:
            self._machine_created = False

    def shutdown(self) -> None:
        try:
            super().shutdown()
        finally:
            self._remove_machine()


__all__ = ["SmolvmInterpreter"]
