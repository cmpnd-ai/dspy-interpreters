# What conformance can prove

The suites deliberately separate DSPy's behavioral contract from backend
security and deployment claims.

## Proven through public behavior

`check_interpreter` can distinguish implementations that lose session state,
share fresh instances, collapse recoverable errors into terminal failures,
break host-tool calls, mishandle typed submission, or permit use after shutdown.
An accepted `SUBMIT` must terminate the current execution; the suite invokes a
host-side sentinel after `SUBMIT` to prove that no later side effect occurs.

`check_execution_instructions` is a separate optional-extension suite. Its
absence does not make an implementation fail the released core protocol: an
interpreter factory without execution instructions contributes no runtime
description. Instructions are factory-level metadata because RLM builds its
action signature before creating an interpreter session.

`check_rlm` runs a real `dspy.RLM`. It proves that a user tool and the LM-shaped
`llm_query` host tool round-trip, that typed submission reaches the real RLM
parser, and that factory ownership invokes shutdown.
`check_rlm_execution_instructions` separately proves that offered instructions
are attached to the action signature. The integration check is an expected
failure on released DSPy 3.3 and passes on current DSPy main. Strict XPASS
exposes the compatibility transition when it reaches a supported release.

`check_flex_facade` runs a real `dspy.Flex` optimized source program. It proves
that the facade source executes, constructs and calls a real host predictor,
calls an approved host tool, transports typed values, and survives save/load
with the interpreter remaining runtime configuration.

## Not provable through `CodeInterpreter`

These properties are intentionally not generic conformance claims because two
implementations can have identical public behavior while differing internally:

- process, VM, Wasm, or container isolation;
- credential secrecy and the absence of credentials inside guest memory;
- filesystem, network, CPU, memory, and wall-clock enforcement;
- whether an LM call used a dedicated broker or an ordinary host-tool bridge;
- whether a `dspy` facade or the native package produced equivalent behavior;
- package inventory, cold start, throughput, persistence duration, and cost.

Backends should test and document these as implementation-specific security,
resource, and operational claims. They must not influence whether DSPy accepts
the object as a `CodeInterpreter` unless core DSPy branches on them.

## Gaps discovered by conformance

1. DSPy's Flex facade imports `types`, uses `globals`, and relies on Python magic
   method behavior outside Monty's subset. The Monty adapter now lowers these
   facade operations and DSPy-module marker inheritance before execution. This
   is dialect adaptation, not a generic interpreter capability.
2. Modal exposes bidirectional streams on a persistent Sandbox process. The
   remote adapter uses framed JSON lines: generated code blocks reading stdin,
   the host executes an approved tool or LM callback, and writes the response.
   No callback server, polling filesystem, or credentials in the guest are
   needed. The adapter passes all suites against both a process-level protocol
   double and live Modal Sandboxes.
