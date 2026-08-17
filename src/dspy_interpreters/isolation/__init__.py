"""Guarantee-based confinement for on-machine interpreters.

Public API::

    from dspy_interpreters.isolation import IsolationSpec, probe

    spec = IsolationSpec.confined(memory="512M", network="none")
    print(probe().to_dict())          # what this machine can enforce
    LocalInterpreter(mode="subprocess", isolation=spec)

The specification names portable *guarantees*.  A backend refuses at
``start()`` when it cannot provide one; it never silently weakens the request.
"""

from dspy_interpreters.isolation._backend import (
    Backend,
    BackendCapabilities,
    LaunchPlan,
    get_backend,
    probe,
    select_backend,
)
from dspy_interpreters.isolation.spec import (
    CLEAN_ENVIRONMENT,
    CPU_TIME_CAPPED,
    FILESYSTEM_ALLOWLIST,
    GUARANTEES,
    KILLED_WITH_HOST,
    MEMORY_CAPPED,
    NO_AMBIENT_NETWORK,
    NO_NEW_PRIVILEGES,
    OWN_ADDRESS_SPACE,
    PRIVATE_TMP,
    PROCESS_COUNT_CAPPED,
    REDUCED_KERNEL_SURFACE,
    WALL_TIME_CAPPED,
    EnvPolicy,
    FilesystemPolicy,
    IsolationError,
    IsolationReport,
    IsolationSpec,
    IsolationSpecError,
    IsolationUnsupportedError,
    NetworkPolicy,
    ResourceLimits,
    parse_memory,
)

__all__ = [
    "CLEAN_ENVIRONMENT",
    "CPU_TIME_CAPPED",
    "FILESYSTEM_ALLOWLIST",
    "GUARANTEES",
    "KILLED_WITH_HOST",
    "MEMORY_CAPPED",
    "NO_AMBIENT_NETWORK",
    "NO_NEW_PRIVILEGES",
    "OWN_ADDRESS_SPACE",
    "PRIVATE_TMP",
    "PROCESS_COUNT_CAPPED",
    "REDUCED_KERNEL_SURFACE",
    "WALL_TIME_CAPPED",
    "Backend",
    "BackendCapabilities",
    "EnvPolicy",
    "FilesystemPolicy",
    "IsolationError",
    "IsolationReport",
    "IsolationSpec",
    "IsolationSpecError",
    "IsolationUnsupportedError",
    "LaunchPlan",
    "NetworkPolicy",
    "ResourceLimits",
    "get_backend",
    "parse_memory",
    "probe",
    "select_backend",
]
