# dspy-interpreters

Interpreter implementations, black-box conformance checks, and reproducible
performance measurements for DSPy's public `CodeInterpreter` protocol.

This repository answers three separate questions:

1. **Correctness:** does an implementation satisfy the behavior RLM and Flex
   actually require?
2. **Performance:** what does construction, startup, execution, host-tool RPC,
   data transfer, shutdown, and memory cost?
3. **Security and operations:** what authority does generated code receive,
   what is isolated, what persists, and which claims have been tested?

Passing conformance is not evidence of isolation. Likewise, a secure sandbox
can still be too slow, too restricted, or incompatible with the Python dialect
a model emits.

## Recommendation

There is no honest universal winner. Choose from the threat model:

| Workload | Recommended backend | Why |
|---|---|---|
| Trusted generated code; latency is paramount | `LocalInterpreter` | Approximately 0.02 ms warm execution and host calls; no serialization or process boundary |
| Untrusted code that fits restricted Python | `MontyInterpreter` | Best measured security/performance balance; approximately 0.12 ms warm execution; no escape found in the adversarial review |
| Trusted local persistent development or real DSPy imports | `IPythonInterpreter` | Full CPython and package environment in a managed subprocess; easier lifecycle control than in-process execution |
| Untrusted full CPython, ephemeral remote session | `ModalInterpreter` | Provider sandbox, network blocked by default, configurable CPU/memory/lifetime; higher latency and provider cost |
| Persistent AI-engineering workspace | `ExeDevInterpreter` | Durable remote Linux VM with full CPython, package installation, filesystem, processes, and network |
| Broad local Python compatibility without native host execution | DSPy Deno/Pyodide | Wasm/Deno boundary and moderate warm speed, but **not recommended as a security default until the confirmed cache and protocol issues below are fixed** |

If DSPy must choose one security-oriented default for arbitrary model-generated
code, Monty is the strongest current candidate for workloads that fit its
restricted dialect. DSPy should not imply that any one backend is simultaneously
full Python, fast, and secure. Full-CPython untrusted work should use a remote
sandbox; trusted work can explicitly opt into Local or IPython.

## Install and instantiate

The core install includes the conformance API, Local, and Modal. Install only
the runtime extras a deployment needs:

```bash
pip install dspy-interpreters
pip install 'dspy-interpreters[monty]'
pip install 'dspy-interpreters[ikernel]'
pip install 'dspy-interpreters[modal]'
pip install 'dspy-interpreters[benchmark]'
```

exe.dev uses the system OpenSSH client and an authenticated exe.dev SSH
configuration, so its `exe` extra has no additional Python dependencies.

```python
from dspy_interpreters import LocalInterpreter, ModalInterpreter
from dspy_interpreters.exe import ExeDevInterpreter
from dspy_interpreters.ikernel import IPythonInterpreter
from dspy_interpreters.monty import MontyInterpreter

trusted = LocalInterpreter()
restricted = MontyInterpreter()
kernel = IPythonInterpreter(execution_timeout=60)
remote = ModalInterpreter(cpu=1, memory=1024, block_network=True)
workspace = ExeDevInterpreter()  # provisions and owns one temporary VM
```

Each implementation supports DSPy's constructor-time `tools` and
`output_fields` shape. They also offer two independent optional extensions:
invocation-scoped `bind()` and stable class/factory-level
`execution_instructions`. DSPy does not need `bind()` for its normal
factory-owned RLM flow; it can configure the mutable protocol state directly.
Callable wrappers around an interpreter class must copy
`execution_instructions` onto the wrapper itself because RLM reads provider
metadata before creating a session. Always call `shutdown()` in a `finally`
block; it terminates local resources and deletes automatically owned remote
resources.

## Same-machine benchmark

The latest complete run measured all six backends from the same Amp orb on
2026-08-13:

- Linux x86-64, 16 reported CPUs;
- Python 3.11.6;
- 3 cold sessions and 20 warm executions per backend;
- 5 samples for the 1 MiB transfer scenario;
- an 8 MiB retained guest allocation for memory measurements;
- live authenticated Modal and exe.dev providers;
- wall-clock milliseconds, shown as **p50 / p95**.

The raw samples, min/max values, environment metadata, and memory fields are in
[`reports/benchmarks-full.json`](reports/benchmarks-full.json). Three cold
samples are enough to expose startup scale but not enough for a statistically
stable provider p95—the cold p95 below is effectively the worst of three runs.
Repeat with at least 20 cold runs, in the deployment region, before making a
large provider commitment.

### Cold lifecycle latency

`time to interactive` includes construction, startup, and the first successful
`40 + 2` execution. Remote construction is intentionally cheap because resource
allocation is lazy. exe.dev shutdown includes SSH worker cleanup and VM deletion;
Modal shutdown includes provider sandbox termination.

| Backend | Construct | Start | First execute | Time to interactive | Shutdown |
|---|---:|---:|---:|---:|---:|
| Local / in-process | 0.001 / 0.004 | <0.001 / <0.001 | 0.026 / 0.076 | **0.028 / 0.081** | 0.001 / 0.001 |
| Monty | 0.014 / 0.016 | 0.002 / 0.002 | 4.185 / 9.368 | **4.201 / 9.387** | 0.538 / 0.776 |
| IPython kernel | 0.088 / 0.091 | 684.980 / 744.187 | 6.714 / 6.981 | **692.049 / 750.906** | 340.041 / 406.073 |
| Modal remote | 0.009 / 0.015 | 1430.967 / 2359.573 | 105.216 / 234.395 | **1575.573 / 2457.971** | 503.583 / 880.493 |
| Deno / Pyodide | 0.145 / 13.359 | 2281.484 / 2406.497 | 3.648 / 6.478 | **2288.100 / 2423.504** | 13.172 / 13.215 |
| exe.dev remote | 0.018 / 0.019 | 4027.926 / 4095.536 | 65.535 / 65.946 | **4093.890 / 4161.089** | 1677.198 / 1810.588 |

### Warm execution and boundary latency

The scalar case executes `6 * 7` in an already-running session. Host-tool RPC
calls `add(left=19, right=23)` and verifies the host observed the call. The 1 MiB
case injects a string through `execute(..., variables=...)` and computes its
length in the guest.

| Backend | Warm scalar | Host-tool round trip | 1 MiB variable |
|---|---:|---:|---:|
| Local / in-process | **0.019 / 0.037** | **0.024 / 0.030** | **0.022 / 0.057** |
| Monty | 0.115 / 0.170 | 0.193 / 0.250 | 2.526 / 3.337 |
| Deno / Pyodide | 2.925 / 3.177 | 3.442 / 4.059 | 78.831 / 86.985 |
| IPython kernel | 4.868 / 5.877 | 5.910 / 56.485 | 444.791 / 453.439 |
| exe.dev remote | 67.135 / 67.539 | 134.594 / 136.515 | 103.521 / 547.774 |
| Modal remote | 123.839 / 199.666 | 230.160 / 320.930 | 167.955 / 544.435 |

Interpretation:

- Local is the latency floor, not a sandbox.
- Monty adds roughly 0.1–0.2 ms for ordinary execution and host callbacks,
  making it the only isolated/restricted option in the same latency class.
- Deno has a large roughly 2.3 s cold start but low single-digit-millisecond
  warm execution and callbacks.
- IPython starts faster than Deno but has slower warm IPC and particularly
  expensive large-variable serialization.
- exe.dev was faster than Modal in warm scalar, callback, and median 1 MiB
  transfer in this orb-to-provider run, but took roughly 4.1 s to provision and
  become interactive.
- Remote p95 transfer variance is substantial. Region, provider load, image
  cache state, and the benchmark host's network path matter.

### Memory and resource footprint

Memory is not universally comparable. Host memory is the benchmark process plus
its local descendants. It sees local kernels, Deno, and local workers but not a
remote provider. Guest RSS is queried through `/proc/self/statm`; unavailable
runtimes report `—`. The allocation column is host process-tree RSS growth from
before startup through retaining an 8 MiB guest string.

| Backend | Host RSS increase after start | Host RSS increase after 8 MiB allocation | Guest RSS before / after allocation |
|---|---:|---:|---:|
| Local / in-process | 0.0 MiB | 9.0 MiB | 99.2 / 108.2 MiB (entire host process) |
| Monty | 0.0 MiB | 26.2 MiB | — |
| Deno / Pyodide | **165.5 MiB** | **212.9 MiB** | — |
| IPython kernel | 61.5 MiB | 123.5 MiB | 61.5 / 100.4 MiB |
| Modal remote | 0.3 MiB locally | 7.7 MiB locally | 15.4 / 29.2 MiB worker RSS |
| exe.dev remote | 7.9 MiB locally | 9.1 MiB locally | 11.7 / 24.9 MiB worker RSS |

Do not read the remote rows as total container or VM usage; they measure only
the remote Python worker and local client processes. Likewise, Monty's zero
startup increase reflects lazy worker behavior rather than zero runtime cost.

## Security and operational tradeoffs

Security is a set of authorities, not a single score. “Subprocess,” “Wasm,”
“container,” and “VM” are implementation facts; they do not by themselves prove
credential secrecy, resource enforcement, or protocol integrity.

| Backend | Isolation boundary | Guest filesystem / process authority | Network default | Limits and cancellation | Principal security caveats |
|---|---|---|---|---|---|
| Local | None; generated code runs in the DSPy process | Full host-user authority and Python object access | Host network | None | Can read credentials, mutate process state, spawn work, corrupt global stdout, or terminate the application |
| Monty | Restricted Monty runtime in worker subprocesses | Denied except explicit mounts and host tools; restricted Python/stdlib subset | Denied | `request_timeout` plus Monty CPU/memory/recursion limits when configured | Smaller language surface; host tools and writable mounts are explicit authority; no formal proof despite adversarial testing |
| Deno / Pyodide | Python Wasm in a permissioned Deno subprocess | Deno permissions are reachable through `import js`; explicit mounts plus unintended shared Deno-cache read | Denied unless enabled | No native per-execution timeout in DSPy 3.3 | Confirmed shared-cache disclosure, stdout protocol forgery, mount basename collision, dependency/cache trust concerns |
| IPython | Local kernel subprocess; **not a security sandbox** | Full host-user filesystem, environment, shell, subprocess, package, and credential authority | Host network | Startup/execution timeout; timed-out kernel becomes terminal | Process lifecycle isolation only; concurrent execution and callback reentrancy remain unsafe |
| Modal | Remote provider sandbox | Remote container/session filesystem; no host filesystem unless a host tool exposes it | Blocked by default | Provider CPU, memory, total timeout, and idle timeout | Guest-controlled stdout can forge/replay protocol frames; trust Modal isolation and control plane; provider cost/availability |
| exe.dev | Remote durable VM | Full Linux VM filesystem, processes, package installation, sudo, and persistent state | Enabled | SSH command/readiness/execution deadlines; forced process cleanup | Guest can forge the in-VM stdout protocol; trust exe.dev VM isolation/control plane; durable resources incur cost until deleted |

### Confirmed adversarial findings

These are reproduced observations, not hypothetical capability labels:

#### Local and IPython are trusted runtimes

- Local's `redirect_stdout` changes process-global `sys.stdout`. Concurrent
  instances can cross-route output and leave host stdout corrupted.
- Local guest code can access all host Python objects, imports, environment,
  files, network, and process APIs by design.
- IPython moves code into a child process but preserves the host user's files,
  environment, credentials, network, and subprocess authority. It is useful for
  lifecycle and persistent development, not for hostile-code isolation.
- IPython rejects/terminalizes timeouts, but concurrent execution can corrupt
  its shared Jupyter/ZMQ client and callback reentrancy can deadlock until the
  timeout.

#### Monty resisted the tested escape vectors

The review attempted class/MRO/subclass traversal, function globals and
closures, traceback/frame access, dynamic import/eval/exec, pickle/marshal,
subprocess/socket access, unmounted file access, callback object leakage,
mount traversal and outbound symlinks, worker-protocol-looking output, memory
exhaustion, recursion exhaustion, and infinite loops. No sandbox escape was
found. CPU/time, memory, and recursion limits stopped the corresponding resource
tests when configured.

That result is evidence, not a formal security proof. An explicit host callback
still runs with host authority, and an explicit writable mount grants authority
over that mount.

#### Deno currently has two high-priority security defects

1. DSPy grants Deno recursive read access to the shared `DENO_DIR` so Pyodide
   can load. Guest Python can call `js.Deno.readTextFileSync(...)` and read an
   unrelated canary placed in that cache without any configured read path.
2. Trusted JSON-RPC responses and guest-accessible `js.console.log()` share
   stdout. A guest forged the expected request ID, caused the host to return
   `"SPOOFED"` instead of the real result, and desynchronized the next request.

Additionally, two mounted host files with the same basename map to one
`/sandbox/<basename>` path; modifying it synchronized the same content into both
host files. Granting write access to the runner, package directory, shared Deno
cache, or an ancestor permits persistent runner/cache modification. Default
configuration does not grant those writes, but DSPy 3.3 does not reject such an
unsafe overlap.

The default Deno permission boundary did prevent arbitrary host-file reads,
`/proc` reads, environment access, network access, and child processes in the
review. The finding is therefore not “unrestricted host compromise”; it is
unintended cache disclosure plus loss of protocol result integrity.

#### Remote providers isolate the host, not their own worker protocol

Modal and exe.dev keep host callable implementations and credentials outside
the guest and authorize callbacks against the current host-side tool map. The
guest cannot call a tool that is not bound. However, the current worker and
generated code share one fully accessible stdout protocol. Guest code can forge
results and replay an explicitly authorized non-idempotent tool call. Fixing
that as a real intra-sandbox security boundary requires a separate broker with
an OS-enforced boundary—not merely random request IDs in the same process.

Live review found no path from Modal guest code to host credentials, host files,
or unbound tools. exe.dev intentionally grants normal VM authority and network;
the VM, rather than the Python worker, is its isolation boundary.

### Credentials and host tools

LM and service credentials should remain in the DSPy host process. All adapters
can expose an LM, `SUBMIT`, and approved functions as host-tool capabilities:

```text
┌─────────────────────────────── Host process ───────────────────────────────┐
│ LM credentials  ──▶  approved callback broker  ──▶  validated JSON result │
└──────────────────────────────────────┬─────────────────────────────────────┘
                                       │ named capability only
                                       ▼
                              ┌──────────────────┐
                              │ Interpreter code │
                              └──────────────────┘
```

This prevents copying credentials into a sandbox, but the callback itself is a
capability. A broadly designed tool can leak secrets or perform arbitrary host
actions even when the sandbox boundary is perfect.

## Persistent development and “real DSPy” inside the interpreter

RLM/Flex conformance does not require the full DSPy package inside the guest.
Today, predictors, LMs, credentials, and ordinary tools can remain host-side
behind a facade/callback bridge. Persistent AI engineering has different needs:

| Backend | Python dialect | Can use real DSPy imports in guest? | Persistence model | Best fit |
|---|---|---|---|---|
| Local | Host CPython | Yes, from the host environment | Process lifetime; host filesystem | Fast trusted optimization loops |
| Monty | Restricted Python subset | No; use DSPy facade and host callbacks | Session namespace; explicit mounts | Restricted RLM/Flex execution |
| Deno / Pyodide | Pyodide/Wasm Python | Generally facade/host bridge, not a normal DSPy installation | Session namespace; explicit mounted files | Portable local execution after security fixes |
| IPython | Full host CPython/IPython | Yes | Kernel namespace plus host filesystem | Trusted notebooks, iterative development, optimizers |
| Modal | Full remote CPython | Not in the current fixed slim image; adding a configurable image could install it | Sandbox session; current image is fixed | Ephemeral isolated full-Python jobs |
| exe.dev | Full remote Linux CPython | Yes; packages and source can be installed in the VM | Durable VM filesystem and processes | Long-running model-driven development and optimization |

Installing DSPy in a remote guest does **not** mean placing LM credentials
there. A future “native DSPy in sandbox” mode should configure DSPy with a
credential-free LM/tool transport back to the host. The facade/native choice is
a runtime binding decision; serialized Flex programs should preserve their code
dialect, not provider credentials or a particular live interpreter instance.

## Conformance status

The suite tests behavior through public interpreter methods: lifecycle,
persistent state, fresh-instance isolation, recoverable error taxonomy, tool
round trips and revocation, typed `SUBMIT`, immediate termination after accepted
submission, terminal shutdown, atomic `bind`, stable execution instructions,
real RLM consumption, and real Flex facade execution/save/load.

| Backend | Core interpreter (11 checks) | `bind` | Execution instructions | Real RLM | Flex facade |
|---|---:|---:|---:|---:|---:|
| Local | Pass | Pass | Pass | Pass | Pass |
| Monty adapter | Pass | Pass | Pass | Pass | Pass |
| Deno / Pyodide on released DSPy 3.3 | Pass | Not implemented | Not implemented | Pass | Pass |
| Deno / Pyodide on current DSPy main | Pass | Not implemented | Pass | Pass | Pass |
| IPython | Pass | Pass | Pass | Pass | Pass |
| Modal process double + live | Pass | Pass | Pass | Pass | Pass |
| exe.dev process double + live | Pass | Pass | Pass | Pass | Pass |

The package supports `dspy>=3.3.0,<4.0`. DSPy 3.2 lacks the public
`CodeExecutionError` and `Flex` APIs required by the suite. Released DSPy 3.3's
base RLM consumer flow passes, but it does not append `execution_instructions`
to its action signature. Current DSPy main includes that integration from PR
#10136. The separate `check_rlm_bind` expected failure tracks an optional
binding experiment, not a missing requirement for normal RLM execution. When
the execution-instructions change reaches a supported release, strict XPASS
makes CI fail until the compatibility marker is deliberately updated.

The raw upstream `dbreunig/dspy-monty-interpreter` remains a useful negative
control: its real RLM flow passes, but execution continues after accepted
`SUBMIT`, untyped output is not normalized, shutdown is not terminal, and Flex
fails on unsupported facade imports. This package's adapter corrects those
contract differences and lowers the current Flex facade dialect.

## Using the conformance suite

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

check_interpreter(MyInterpreter).raise_for_failures()
check_bind(MyInterpreter).raise_for_failures()
check_execution_instructions(MyInterpreter).raise_for_failures()
check_rlm(MyInterpreter).raise_for_failures()
check_flex_facade(MyInterpreter).raise_for_failures()

# Optional DSPy integration checks. Both strict-xfail on released DSPy 3.3;
# execution instructions pass on current DSPy main, while bind is experimental.
check_rlm_bind(MyInterpreter).raise_for_failures()
check_rlm_execution_instructions(MyInterpreter).raise_for_failures()
```

Reports can be collected and serialized instead of raised immediately:

```python
report = check_interpreter(MyInterpreter)
report.to_json("conformance.json")
print(report.failed_ids)
```

Generated pytest parameters are available through
`dspy_interpreters.pytest.parametrize_interpreter`. See
[`docs/abstraction-boundaries.md`](docs/abstraction-boundaries.md) for what the
public suite can and cannot prove.

## Reproducing the benchmark

Credential-free local run:

```bash
uv sync --all-extras
uv run --with 'deno>=2.4.5,<3' \
  python scripts/run_benchmarks.py \
  --cold-runs 3 --warm-runs 20 --strict \
  --output reports/benchmarks-latest.json
```

Complete live-provider run:

```bash
uv run --with 'deno>=2.4.5,<3' \
  python scripts/run_benchmarks.py \
  --modal --exe \
  --cold-runs 3 --warm-runs 20 --strict \
  --output reports/benchmarks-full.json
```

Live runs consume provider resources. Modal authentication and exe.dev SSH
authentication must already work. `ExeDevInterpreter` bounds SSH control,
readiness, and execution operations, force-terminates stalled SSH clients,
removes uploaded workers, and deletes automatically provisioned VMs during
normal shutdown and failed startup cleanup.

The benchmark intentionally has no fixed latency threshold: hosted-runner and
provider variance would make that gate noisy. CI does require every selected
scenario to complete, publishes p50/p95 in the job summary and PR comment, and
uploads the raw JSON report. See [`docs/benchmarking.md`](docs/benchmarking.md)
for the detailed methodology and memory caveats.

## Development and releases

Pull requests and pushes to `main` test minimum direct dependency versions on
Python 3.10 and newest compatible versions on Python 3.12, run the conformance
suite, build distributions, and publish the credential-free benchmark report.
Releases use reviewed GitHub Releases and PyPI Trusted Publishing; see
[`docs/releasing.md`](docs/releasing.md).
