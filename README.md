# dspy-interpreters

Black-box conformance checks and optional interpreter backends for DSPy's
public `CodeInterpreter` protocol.

```python
from dspy_interpreters import (
    check_bind,
    check_execution_instructions,
    check_flex_facade,
    check_interpreter,
    check_rlm,
)

report = check_interpreter(MyInterpreter)
report.raise_for_failures()
report.to_json("conformance.json")

check_rlm(MyInterpreter).raise_for_failures()
check_flex_facade(MyInterpreter).raise_for_failures()

# Optional extensions proposed for the next DSPy release.
check_bind(MyInterpreter).raise_for_failures()
check_execution_instructions(MyInterpreter).raise_for_failures()
```

The same generated checks are available to pytest through
`dspy_interpreters.pytest.parametrize_interpreter`.

## Backends

- `LocalInterpreter`: fastest trusted in-process CPython; no isolation.
- `dspy_interpreters.monty.MontyInterpreter`: restricted subprocess runtime,
  installed with the `monty` extra. Includes Flex facade dialect lowering.
- `ModalInterpreter`: persistent remote Modal Sandbox with synchronous
  stdin/stdout host-tool RPC, installed with the `modal` extra.
- DSPy's Deno/Pyodide interpreter is exercised as the reference backend.

The upstream `dbreunig/dspy-monty-interpreter` passes the real RLM consumer
suite without this package's adapter and currently fails the Flex facade suite
because Monty does not provide the facade's `types` import. It also exposes a
real contract defect: execution continues after an accepted `SUBMIT`. This
package's adapter routes `SUBMIT` through a terminating host call; the raw
upstream implementation remains a negative control for that core check.
