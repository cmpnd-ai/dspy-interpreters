"""IsolationSpec, presets, reports, errors, and backend selection (platform-independent)."""

from __future__ import annotations

import sys
import types

import pytest
from dspy import CodeInterpreterError

from dspy_interpreters.isolation import (
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
    BackendCapabilities,
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
    select_backend,
)
from dspy_interpreters.isolation import _backend as backend_module

# --------------------------------------------------------------------------- #
# parse_memory
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1024, 1024),
        ("1024", 1024),
        ("512M", 512 * 1024**2),
        ("512m", 512 * 1024**2),
        ("512MB", 512 * 1024**2),
        ("512MiB", 512 * 1024**2),
        ("2GiB", 2 * 1024**3),
        ("2G", 2 * 1024**3),
        ("1.5g", int(1.5 * 1024**3)),
        ("4k", 4096),
        ("1T", 1024**4),
        (" 8 KB ", 8192),
        ("100b", 100),
    ],
)
def test_parse_memory_accepts_sizes(value, expected):
    assert parse_memory(value) == expected


@pytest.mark.parametrize("value", [0, -1, "0", "-5M", "", "abc", "1X", "1 2M", True, 1.5, None, [1]])
def test_parse_memory_rejects_invalid(value):
    with pytest.raises(IsolationSpecError):
        parse_memory(value)


def test_parse_memory_error_is_a_value_error_and_a_code_interpreter_error():
    with pytest.raises(ValueError):
        parse_memory("nope")
    with pytest.raises(CodeInterpreterError):
        parse_memory("nope")


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


def test_default_spec_is_valid_and_unconfined():
    spec = IsolationSpec()
    assert spec.files is None
    assert spec.network.mode == "host"
    assert spec.env.mode == "inherit"
    assert spec.require == frozenset()
    assert spec.is_confined is False
    assert spec.guarantees() == frozenset({OWN_ADDRESS_SPACE, KILLED_WITH_HOST})


def test_require_is_normalized_to_frozenset():
    spec = IsolationSpec(require={NO_NEW_PRIVILEGES})
    assert isinstance(spec.require, frozenset)
    assert spec.require == frozenset({NO_NEW_PRIVILEGES})


def test_unknown_guarantee_in_require_is_rejected():
    with pytest.raises(IsolationSpecError, match="unknown guarantees"):
        IsolationSpec(require={"teleportation"})


@pytest.mark.parametrize(
    "kwargs",
    [
        {"network": NetworkPolicy(mode="bridge")},
        {"env": EnvPolicy(mode="dirty")},
        {"limits": ResourceLimits(memory="lots")},
        {"limits": ResourceLimits(memory=0)},
        {"limits": ResourceLimits(cpu_seconds=0)},
        {"limits": ResourceLimits(cpu_seconds=-3)},
        {"limits": ResourceLimits(cpu_seconds=True)},
        {"limits": ResourceLimits(cpu_seconds="10")},
        {"limits": ResourceLimits(wall_time_seconds=0)},
        {"limits": ResourceLimits(max_processes=0)},
        {"limits": ResourceLimits(max_processes=2.5)},
        {"limits": ResourceLimits(max_processes=True)},
        {"files": FilesystemPolicy(read="/etc")},
        {"files": FilesystemPolicy(read=("",))},
        {"files": FilesystemPolicy(write=(1,))},
        {"files": FilesystemPolicy(workdir=5)},
        {"env": EnvPolicy(passthrough=["PATH"])},
        {"env": EnvPolicy(passthrough=(1,))},
        {"env": EnvPolicy(variables={"A": 1})},
        {"env": EnvPolicy(variables={1: "a"})},
    ],
)
def test_invalid_specs_raise_spec_error(kwargs):
    with pytest.raises(IsolationSpecError):
        IsolationSpec(**kwargs)


def test_spec_error_hierarchy():
    assert issubclass(IsolationSpecError, IsolationError)
    assert issubclass(IsolationSpecError, ValueError)
    assert issubclass(IsolationError, CodeInterpreterError)
    assert issubclass(IsolationUnsupportedError, IsolationError)


def test_valid_spec_accepts_every_field():
    spec = IsolationSpec(
        files=FilesystemPolicy(
            read=("/data",), write=("/out",), include_runtime=False, private_tmp=False, workdir="/w"
        ),
        network=NetworkPolicy(mode="none"),
        limits=ResourceLimits(memory="1G", cpu_seconds=2.5, max_processes=3, wall_time_seconds=10),
        env=EnvPolicy(mode="clean", passthrough=("HOME",), variables={"A": "b"}),
        require={NO_NEW_PRIVILEGES, REDUCED_KERNEL_SURFACE},
        backend_options={"linux.launcher": "native"},
    )
    assert spec.limits.memory_bytes == 1024**3
    assert spec.backend_options["linux.launcher"] == "native"


def test_spec_is_frozen():
    spec = IsolationSpec()
    with pytest.raises(AttributeError):
        spec.network = NetworkPolicy(mode="none")  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# guarantees() derivation
# --------------------------------------------------------------------------- #


def test_guarantees_from_files():
    spec = IsolationSpec(files=FilesystemPolicy())
    assert spec.guarantees() == frozenset({OWN_ADDRESS_SPACE, KILLED_WITH_HOST, FILESYSTEM_ALLOWLIST, PRIVATE_TMP})
    spec = IsolationSpec(files=FilesystemPolicy(private_tmp=False))
    assert PRIVATE_TMP not in spec.guarantees()
    assert FILESYSTEM_ALLOWLIST in spec.guarantees()
    assert spec.is_confined


def test_guarantees_from_network_limits_env_and_require():
    spec = IsolationSpec(network=NetworkPolicy(mode="none"))
    assert NO_AMBIENT_NETWORK in spec.guarantees()
    spec = IsolationSpec(limits=ResourceLimits(memory="1M"))
    assert MEMORY_CAPPED in spec.guarantees()
    spec = IsolationSpec(limits=ResourceLimits(cpu_seconds=1))
    assert CPU_TIME_CAPPED in spec.guarantees()
    spec = IsolationSpec(limits=ResourceLimits(max_processes=1))
    assert PROCESS_COUNT_CAPPED in spec.guarantees()
    spec = IsolationSpec(limits=ResourceLimits(wall_time_seconds=1))
    assert WALL_TIME_CAPPED in spec.guarantees()
    assert spec.is_confined is False  # wall time alone does not need a confinement backend
    spec = IsolationSpec(env=EnvPolicy(mode="clean"))
    assert CLEAN_ENVIRONMENT in spec.guarantees()
    assert spec.is_confined
    spec = IsolationSpec(require={NO_NEW_PRIVILEGES})
    assert NO_NEW_PRIVILEGES in spec.guarantees()
    assert spec.is_confined


def test_every_guarantee_has_a_description():
    for name in (
        OWN_ADDRESS_SPACE,
        FILESYSTEM_ALLOWLIST,
        NO_AMBIENT_NETWORK,
        MEMORY_CAPPED,
        CPU_TIME_CAPPED,
        PROCESS_COUNT_CAPPED,
        WALL_TIME_CAPPED,
        CLEAN_ENVIRONMENT,
        PRIVATE_TMP,
        KILLED_WITH_HOST,
        NO_NEW_PRIVILEGES,
        REDUCED_KERNEL_SURFACE,
    ):
        assert GUARANTEES[name]
    assert len(GUARANTEES) == 12


# --------------------------------------------------------------------------- #
# presets and describe()
# --------------------------------------------------------------------------- #


def test_trusted_preset():
    spec = IsolationSpec.trusted()
    assert spec == IsolationSpec()
    assert spec.is_confined is False
    timed = IsolationSpec.trusted(wall_time_seconds=5)
    assert timed.limits.wall_time_seconds == 5
    assert timed.is_confined is False
    assert WALL_TIME_CAPPED in timed.guarantees()


def test_confined_preset_defaults():
    spec = IsolationSpec.confined()
    assert spec.files == FilesystemPolicy()
    assert spec.network.mode == "none"
    assert spec.limits == ResourceLimits(memory="1G", cpu_seconds=120.0, max_processes=32, wall_time_seconds=120.0)
    assert spec.env.mode == "clean"
    assert spec.guarantees() == frozenset(
        {
            OWN_ADDRESS_SPACE,
            KILLED_WITH_HOST,
            FILESYSTEM_ALLOWLIST,
            PRIVATE_TMP,
            NO_AMBIENT_NETWORK,
            MEMORY_CAPPED,
            CPU_TIME_CAPPED,
            PROCESS_COUNT_CAPPED,
            WALL_TIME_CAPPED,
            CLEAN_ENVIRONMENT,
        }
    )


def test_confined_preset_overrides():
    spec = IsolationSpec.confined(
        read=["/data"],
        write=["/out"],
        workdir="/w",
        network="host",
        memory=None,
        cpu_seconds=None,
        max_processes=None,
        wall_time_seconds=None,
        env_passthrough=["HOME"],
        require={NO_NEW_PRIVILEGES},
        backend_options={"linux.launcher": "bwrap"},
    )
    assert spec.files == FilesystemPolicy(read=("/data",), write=("/out",), workdir="/w")
    assert spec.network.mode == "host"
    assert spec.limits == ResourceLimits()
    assert spec.env == EnvPolicy(mode="clean", passthrough=("HOME",))
    assert spec.require == frozenset({NO_NEW_PRIVILEGES})
    assert spec.backend_options == {"linux.launcher": "bwrap"}
    assert spec.guarantees() == frozenset(
        {OWN_ADDRESS_SPACE, KILLED_WITH_HOST, FILESYSTEM_ALLOWLIST, PRIVATE_TMP, CLEAN_ENVIRONMENT, NO_NEW_PRIVILEGES}
    )


def test_describe_is_stable():
    assert IsolationSpec().describe() == ("host filesystem; host network; no resource limits; inherited environment")
    assert IsolationSpec.confined().describe() == (
        "filesystem limited to an allowlist; no network access; "
        "limits: memory 1G, CPU 120s, processes 32, wall time 120s per execution; clean environment"
    )
    assert IsolationSpec.trusted(wall_time_seconds=2.5).describe() == (
        "host filesystem; host network; limits: wall time 2.5s per execution; inherited environment"
    )
    assert IsolationSpec(limits=ResourceLimits(memory=1024)).describe() == (
        "host filesystem; host network; limits: memory 1024; inherited environment"
    )


# --------------------------------------------------------------------------- #
# IsolationReport
# --------------------------------------------------------------------------- #


def test_report_extras_missing_and_to_dict():
    report = IsolationReport(
        backend="fake",
        platform="linux",
        requested={OWN_ADDRESS_SPACE, MEMORY_CAPPED, KILLED_WITH_HOST},
        guarantees={
            OWN_ADDRESS_SPACE: "separate worker process",
            KILLED_WITH_HOST: "PR_SET_PDEATHSIG",
            NO_NEW_PRIVILEGES: "prctl(PR_SET_NO_NEW_PRIVS)",
        },
        notes=["one", "two"],
    )
    assert isinstance(report.requested, frozenset)
    assert isinstance(report.notes, tuple)
    assert report.extras == {NO_NEW_PRIVILEGES: "prctl(PR_SET_NO_NEW_PRIVS)"}
    assert report.missing == frozenset({MEMORY_CAPPED})
    assert report.to_dict() == {
        "backend": "fake",
        "platform": "linux",
        "requested": [KILLED_WITH_HOST, MEMORY_CAPPED, OWN_ADDRESS_SPACE],
        "guarantees": {
            KILLED_WITH_HOST: "PR_SET_PDEATHSIG",
            NO_NEW_PRIVILEGES: "prctl(PR_SET_NO_NEW_PRIVS)",
            OWN_ADDRESS_SPACE: "separate worker process",
        },
        "notes": ["one", "two"],
    }


def test_report_without_missing_or_extras():
    report = IsolationReport(
        backend="b", platform="p", requested=[OWN_ADDRESS_SPACE], guarantees={OWN_ADDRESS_SPACE: "x"}
    )
    assert report.missing == frozenset()
    assert report.extras == {}
    assert report.notes == ()


def test_report_to_dict_is_json_serializable():
    import json

    report = IsolationReport(
        backend="b", platform="p", requested={OWN_ADDRESS_SPACE}, guarantees={OWN_ADDRESS_SPACE: "x"}
    )
    assert json.loads(json.dumps(report.to_dict()))["backend"] == "b"


# --------------------------------------------------------------------------- #
# IsolationUnsupportedError
# --------------------------------------------------------------------------- #


def test_unsupported_error_message_and_fields():
    error = IsolationUnsupportedError({MEMORY_CAPPED: "no cgroups", NO_AMBIENT_NETWORK: "no userns"}, backend="linux")
    assert error.unmet == {MEMORY_CAPPED: "no cgroups", NO_AMBIENT_NETWORK: "no userns"}
    assert error.backend == "linux"
    message = str(error)
    assert message.startswith("Requested isolation guarantees are not available on backend 'linux': ")
    assert "memory_capped: no cgroups" in message
    assert "no_ambient_network: no userns" in message
    assert isinstance(error, CodeInterpreterError)


def test_unsupported_error_without_backend():
    error = IsolationUnsupportedError({MEMORY_CAPPED: "why"})
    assert error.backend is None
    assert str(error) == "Requested isolation guarantees are not available: memory_capped: why"


# --------------------------------------------------------------------------- #
# select_backend
# --------------------------------------------------------------------------- #


class FakeBackend:
    def __init__(self, name: str, platform: str, supported: dict[str, str], unsupported: dict[str, str] | None = None):
        self.name = name
        self._caps = BackendCapabilities(
            name=name, platform=platform, supported=dict(supported), unsupported=dict(unsupported or {})
        )
        self.calls = 0

    def capabilities(self) -> BackendCapabilities:
        self.calls += 1
        return self._caps

    def plan(self, spec, *, python, worker_path, session_dir):  # pragma: no cover - not used here
        raise NotImplementedError

    def attach(self, process, plan) -> None:  # pragma: no cover - not used here
        return None

    def kill(self, process, plan) -> None:  # pragma: no cover - not used here
        return None


_BASE = {OWN_ADDRESS_SPACE: "process", KILLED_WITH_HOST: "watchdog", WALL_TIME_CAPPED: "host deadline"}


def _install_fake_backends(monkeypatch, backends: dict[str, FakeBackend]) -> dict[str, FakeBackend]:
    """Route get_backend(platform) to fakes and give select_backend a fake PlainBackend module."""

    def fake_get_backend(platform=sys.platform):
        key = "linux" if platform.startswith("linux") else platform
        return backends.get(key) or backends["other"]

    monkeypatch.setattr(backend_module, "get_backend", fake_get_backend)
    plain = FakeBackend("plain", "any", _BASE)
    fake_plain_module = types.ModuleType("dspy_interpreters.isolation._plain")
    fake_plain_module.PlainBackend = lambda platform=sys.platform: plain  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "dspy_interpreters.isolation._plain", fake_plain_module)
    backends["plain"] = plain
    return backends


def _fakes(monkeypatch) -> dict[str, FakeBackend]:
    all_supported = {name: "mechanism" for name in GUARANTEES}
    linux = FakeBackend("linux", "linux", all_supported)
    darwin_supported = {k: v for k, v in all_supported.items() if k not in (MEMORY_CAPPED, NO_NEW_PRIVILEGES)}
    darwin = FakeBackend(
        "darwin",
        "darwin",
        darwin_supported,
        {MEMORY_CAPPED: "macOS does not enforce RLIMIT_AS", NO_NEW_PRIVILEGES: "not implemented"},
    )
    win32 = FakeBackend(
        "windows",
        "win32",
        {**_BASE, MEMORY_CAPPED: "job object", CPU_TIME_CAPPED: "job object", CLEAN_ENVIRONMENT: "env"},
        {FILESYSTEM_ALLOWLIST: "requires AppContainer", NO_AMBIENT_NETWORK: "requires AppContainer"},
    )
    other = FakeBackend("plain", "freebsd", _BASE)
    return _install_fake_backends(monkeypatch, {"linux": linux, "darwin": darwin, "win32": win32, "other": other})


def test_select_backend_unconfined_uses_plain(monkeypatch):
    fakes = _fakes(monkeypatch)
    for platform in ("linux", "darwin", "win32", "freebsd"):
        assert select_backend(IsolationSpec(), platform=platform) is fakes["plain"]
        assert select_backend(IsolationSpec.trusted(wall_time_seconds=3), platform=platform) is fakes["plain"]
    assert fakes["linux"].calls == 0


def test_select_backend_linux_accepts_confined(monkeypatch):
    fakes = _fakes(monkeypatch)
    spec = IsolationSpec.confined(require={NO_NEW_PRIVILEGES, REDUCED_KERNEL_SURFACE})
    assert select_backend(spec, platform="linux") is fakes["linux"]
    assert select_backend(spec, platform="linux2") is fakes["linux"]
    assert fakes["linux"].calls == 2


def test_select_backend_darwin_refuses_memory_and_no_new_privileges(monkeypatch):
    fakes = _fakes(monkeypatch)
    assert select_backend(IsolationSpec.confined(memory=None), platform="darwin") is fakes["darwin"]
    with pytest.raises(IsolationUnsupportedError) as info:
        select_backend(IsolationSpec.confined(require={NO_NEW_PRIVILEGES}), platform="darwin")
    assert info.value.backend == "darwin"
    assert info.value.unmet == {
        MEMORY_CAPPED: "macOS does not enforce RLIMIT_AS",
        NO_NEW_PRIVILEGES: "not implemented",
    }


def test_select_backend_win32_refuses_filesystem_and_network(monkeypatch):
    fakes = _fakes(monkeypatch)
    ok = IsolationSpec(limits=ResourceLimits(memory="1M", cpu_seconds=1), env=EnvPolicy(mode="clean"))
    assert select_backend(ok, platform="win32") is fakes["win32"]
    with pytest.raises(IsolationUnsupportedError) as info:
        select_backend(IsolationSpec.confined(memory=None, cpu_seconds=None, max_processes=None), platform="win32")
    assert info.value.backend == "windows"
    assert set(info.value.unmet) == {FILESYSTEM_ALLOWLIST, NO_AMBIENT_NETWORK, PRIVATE_TMP}
    assert info.value.unmet[FILESYSTEM_ALLOWLIST] == "requires AppContainer"
    # Guarantees the backend never mentions get the generic reason.
    assert info.value.unmet[PRIVATE_TMP] == "not provided by this backend"


def test_select_backend_other_platform_refuses_everything_confined(monkeypatch):
    fakes = _fakes(monkeypatch)
    with pytest.raises(IsolationUnsupportedError) as info:
        select_backend(IsolationSpec(network=NetworkPolicy(mode="none")), platform="freebsd")
    assert info.value.backend == "plain"
    assert info.value.unmet == {NO_AMBIENT_NETWORK: "not provided by this backend"}
    assert fakes["other"].calls == 1


def test_select_backend_unmet_reasons_are_sorted_by_guarantee(monkeypatch):
    _fakes(monkeypatch)
    with pytest.raises(IsolationUnsupportedError) as info:
        select_backend(IsolationSpec.confined(), platform="freebsd")
    assert list(info.value.unmet) == sorted(info.value.unmet)
    assert OWN_ADDRESS_SPACE not in info.value.unmet
    assert KILLED_WITH_HOST not in info.value.unmet


# --- real backends' static capability tables ------------------------------- #


def test_real_darwin_backend_static_refusals():
    with pytest.raises(IsolationUnsupportedError) as info:
        select_backend(IsolationSpec(limits=ResourceLimits(memory="1M")), platform="darwin")
    assert info.value.unmet[MEMORY_CAPPED] == "macOS does not enforce RLIMIT_AS; no cgroup equivalent"
    with pytest.raises(IsolationUnsupportedError) as info:
        select_backend(IsolationSpec(require={NO_NEW_PRIVILEGES, REDUCED_KERNEL_SURFACE}), platform="darwin")
    assert set(info.value.unmet) == {NO_NEW_PRIVILEGES, REDUCED_KERNEL_SURFACE}


def test_real_win32_backend_static_refusals():
    with pytest.raises(IsolationUnsupportedError) as info:
        select_backend(IsolationSpec(files=FilesystemPolicy(), network=NetworkPolicy(mode="none")), platform="win32")
    assert info.value.unmet[FILESYSTEM_ALLOWLIST] == "requires AppContainer/ACL confinement; not implemented"
    assert info.value.unmet[NO_AMBIENT_NETWORK] == "requires AppContainer network capability model; not implemented"
    with pytest.raises(IsolationUnsupportedError) as info:
        select_backend(IsolationSpec(require={NO_NEW_PRIVILEGES, REDUCED_KERNEL_SURFACE}), platform="win32")
    assert NO_NEW_PRIVILEGES in info.value.unmet
    assert REDUCED_KERNEL_SURFACE in info.value.unmet


def test_backend_capabilities_to_dict_sorted():
    caps = BackendCapabilities(
        name="n", platform="p", supported={"b": "1", "a": "2"}, unsupported={"z": "r"}, notes=["x"]
    )
    assert caps.to_dict() == {
        "name": "n",
        "platform": "p",
        "supported": {"a": "2", "b": "1"},
        "unsupported": {"z": "r"},
        "notes": ["x"],
    }
