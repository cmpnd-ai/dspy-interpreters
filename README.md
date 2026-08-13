# dspy-interpreters

Black-box conformance checks and optional interpreter backends for DSPy's
public `CodeInterpreter` protocol.

## DSPy compatibility

The package supports `dspy>=3.3.0,<4.0`. DSPy 3.2 lacks the public
`CodeExecutionError` and `Flex` APIs required by the suite. DSPy 3.3 supports
the base RLM consumer contract; its pending bind and execution-instruction
integrations are exposed as separate checks and tracked as strict expected
failures until they reach a DSPy release.

```python
from dspy_interpreters import (
    check_bind,
    check_execution_instructions,
    check_flex_facade,
    check_interpreter,
    check_rlm,
    check_rlm_bind,
    check_rlm_execution_instructions,
)

report = check_interpreter(MyInterpreter)
report.raise_for_failures()
report.to_json("conformance.json")

check_rlm(MyInterpreter).raise_for_failures()
check_flex_facade(MyInterpreter).raise_for_failures()

# Optional extensions proposed for the next DSPy release.
check_bind(MyInterpreter).raise_for_failures()
check_execution_instructions(MyInterpreter).raise_for_failures()

# DSPy-core integrations; expected to fail on DSPy 3.3.0.
check_rlm_bind(MyInterpreter).raise_for_failures()
check_rlm_execution_instructions(MyInterpreter).raise_for_failures()
```

The same generated checks are available to pytest through
`dspy_interpreters.pytest.parametrize_interpreter`.

Performance is intentionally reported separately from correctness conformance:

```bash
uv run python scripts/run_benchmarks.py --cold-runs 3 --warm-runs 20
uv run python scripts/run_benchmarks.py --modal  # live provider, consumes resources
uv run python scripts/run_benchmarks.py --exe    # requires exe.dev SSH authentication
```

The benchmark preserves raw samples and reports median and p95 startup,
time-to-interactive, warm execution, host-tool callback, 1 MiB variable transfer,
shutdown, host process-tree RSS, and guest RSS where the runtime exposes it. See
[the methodology](docs/benchmarking.md).

## Development and releases

Pull requests and pushes to `main` test the lowest direct dependency versions
on Python 3.10 and the latest compatible versions on Python 3.12, then build the
package. Releases use reviewed GitHub Releases and PyPI Trusted Publishing; see
[the release guide](docs/releasing.md).

## Backends

- `LocalInterpreter`: fastest trusted in-process CPython; no isolation.
- `IPythonInterpreter` (`IKernelInterpreter` alias): persistent local IPython
  kernel subprocess, installed with the `ikernel` extra. Full host authority;
  process lifecycle isolation is not a security sandbox.
- `dspy_interpreters.monty.MontyInterpreter`: restricted subprocess runtime,
  installed with the `monty` extra. Includes Flex facade dialect lowering.
- `ModalInterpreter`: persistent remote Modal Sandbox with synchronous
  stdin/stdout host-tool RPC, installed with the `modal` extra.
- `ExeDevInterpreter`: persistent remote CPython in a durable exe.dev VM,
  provisioned and controlled over SSH. It uses the same host-tool RPC without
  placing callable code or credentials in the VM.
- DSPy's Deno/Pyodide interpreter is exercised as the reference backend.

The upstream `dbreunig/dspy-monty-interpreter` passes the real RLM consumer
suite without this package's adapter and currently fails the Flex facade suite
because Monty does not provide the facade's `types` import. It also exposes a
real contract defect: execution continues after an accepted `SUBMIT`. This
package's adapter routes `SUBMIT` through a terminating host call; the raw
upstream implementation remains a negative control for that core check.
