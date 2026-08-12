# Releasing

Releases use an explicit version in `pyproject.toml`, a matching Git tag, and
PyPI Trusted Publishing. No long-lived PyPI token is stored in GitHub.

## One-time setup

1. In PyPI's publishing settings, add a pending trusted publisher with:
   - PyPI project name: `dspy-interpreters`
   - GitHub owner: `cmpnd-ai`
   - GitHub repository: `dspy-interpreters`
   - Workflow: `release.yml`
   - Environment: `pypi`
2. In GitHub, create the `pypi` environment. Require a maintainer's approval
   and restrict deployment to tags matching `v*`.
3. Before the first release, replace the temporary DSPy Git source pin with a
   released DSPy version containing the required interpreter extensions, and
   raise the package's minimum `dspy` dependency to that version.

The package name was unregistered when this workflow was added. PyPI's pending
publisher flow creates it during the first trusted publication.

## Release checklist

1. Update `project.version` in `pyproject.toml` using semantic versioning.
2. Run `uv lock`, `uv run ruff check src tests scripts`, and `uv run pytest -q`.
3. Merge the version change through a pull request and wait for CI.
4. Create a GitHub Release from `main` with tag `vX.Y.Z` matching the project
   version exactly.
5. Approve the `pypi` environment deployment after the build job passes.

The release workflow checks that the tag matches the package version and that
the tagged commit is reachable from `main`. It builds once in an unprivileged
job, uploads that exact artifact, and gives OIDC permission only to the separate
publish job. Trusted Publishing also creates PyPI attestations for the uploaded
distributions. Running the workflow manually exercises the build job without
publishing anything.

## When to add more automation

Keep explicit version pull requests while the API and release cadence are
young. If releases become frequent, Release Please is a reasonable next step:
it can maintain the changelog and version PR while preserving the same reviewed
GitHub Release and Trusted Publishing boundary. Dynamic versions derived only
from Git tags remove one manual edit, but make local and pre-release versioning
less obvious and are not needed yet.
