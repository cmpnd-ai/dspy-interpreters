# Interpreter performance benchmarks

Correctness conformance and performance answer different questions. A backend
passes conformance deterministically; speed and memory depend on the machine,
provider region, image cache, network, and current service load. Performance is
therefore a sibling suite and never changes an interpreter's pass/fail status.

## Scenarios

`benchmark_interpreter` runs identical public-API operations against each
backend:

1. construct, start, execute `40 + 2`, and shut down a fresh interpreter;
2. repeatedly execute a scalar expression in one warm session;
3. repeatedly call a host tool through the interpreter boundary;
4. inject and measure a 1 MiB string variable;
5. retain an 8 MiB string in the interpreter namespace;
6. shut down the session.

Every timing retains its raw wall-clock samples and reports median, p95,
minimum, and maximum. `time_to_interactive` covers construction through the
first completed command. Increase `--cold-runs` for provider comparisons; one
run is useful only as a smoke test.

## Memory

With the `benchmark` extra installed, host memory is the RSS of the benchmark
process and all local descendants. That captures local kernel, Deno, and worker
processes, but cannot see a remote provider's processes. Guest RSS is measured
by executing a `/proc/self/statm` query through the public interpreter API.
Runtimes without `/proc` or the required Python features report `null` rather
than failing the benchmark.

These values are not directly interchangeable:

- in-process guest RSS is the whole benchmark process;
- local-subprocess guest RSS is the interpreter process;
- remote guest RSS is the Python worker, not total VM/container memory;
- host process-tree RSS for a remote backend excludes provider memory.

The report records all of these fields explicitly instead of presenting one
misleading universal “memory usage” number.

## Reproduction

Install all local backends and Deno, then run:

```bash
uv sync --all-extras
uv run --with 'deno>=2.4.5,<3' \
  python scripts/run_benchmarks.py --cold-runs 3 --warm-runs 20
```

Add `--modal` or `--exe` only when the corresponding provider is authenticated.
Live runs provision billable resources. exe.dev uses existing OpenSSH
credentials and deletes VMs created by the benchmark during shutdown.

Compare reports only when their recorded environment and run parameters are
appropriate. For provider decisions, run from the deployment region, use at
least 20 cold samples, and repeat at multiple times of day.

## Continuous integration

Every pull request and push to `main` benchmarks the four credential-free local
backends on a GitHub-hosted Python 3.12 runner with three cold starts and 20
warm samples. The workflow publishes:

- a Markdown table in the Actions job summary;
- an automatically updated pull request comment that compares timing p50/p95
  changes with the benchmark artifact for the pull request's base commit;
- the complete JSON report as the `interpreter-benchmark-report` artifact for
  30 days;
- a failed benchmark job if any selected backend cannot complete its scenarios.

CI numbers are useful for detecting large regressions and comparing backends on
the same run. GitHub-hosted runner variance makes them unsuitable as strict
latency thresholds. Modal and exe.dev remain opt-in manual benchmarks because
ordinary CI should not require provider credentials or provision paid resources.

PR comments are posted by a separate `workflow_run` workflow. It never checks
out or executes pull request code with a write-capable token, so reports can be
posted safely for contributions from forks.
