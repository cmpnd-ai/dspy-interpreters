"""Windows backend: pure ctypes/flag tests on every OS, live job-object tests only on win32."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys

import pytest

from dspy_interpreters.isolation import (
    CLEAN_ENVIRONMENT,
    CPU_TIME_CAPPED,
    FILESYSTEM_ALLOWLIST,
    KILLED_WITH_HOST,
    MEMORY_CAPPED,
    NO_AMBIENT_NETWORK,
    NO_NEW_PRIVILEGES,
    PROCESS_COUNT_CAPPED,
    REDUCED_KERNEL_SURFACE,
    EnvPolicy,
    IsolationSpec,
    IsolationUnsupportedError,
    ResourceLimits,
    select_backend,
)
from dspy_interpreters.isolation._backend import LaunchPlan, get_backend
from dspy_interpreters.isolation._windows import (
    CREATE_NEW_PROCESS_GROUP,
    CREATE_NO_WINDOW,
    IO_COUNTERS,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOB_OBJECT_LIMIT_PROCESS_TIME,
    JOB_OBJECT_UILIMIT_ALL,
    JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObject,
    WindowsBackend,
    extended_limit_information,
    job_limits,
)

is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8


def _session(tmp_path):
    session = tmp_path / "session"
    for name in ("bootstrap", "work", "tmp"):
        (session / name).mkdir(parents=True)
    worker = session / "bootstrap" / "worker.py"
    worker.write_text("print('worker')\n")
    return str(session), str(worker)


# --------------------------------------------------------------------------- #
# job_limits (pure)
# --------------------------------------------------------------------------- #


def test_job_limits_defaults():
    flags, fields = job_limits()
    assert flags == JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
    assert fields == {}


def test_job_limits_flag_math_and_100ns_conversion():
    flags, fields = job_limits(memory_bytes=512 * 1024**2, cpu_seconds=2.5, max_processes=8)
    assert flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY
    assert flags & JOB_OBJECT_LIMIT_PROCESS_TIME
    assert flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    assert flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    assert flags & JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
    assert flags == 0x100 | 0x2 | 0x8 | 0x2000 | 0x400
    assert fields["ProcessMemoryLimit"] == 512 * 1024**2
    assert fields["PerProcessUserTimeLimit"] == 25_000_000  # 2.5 s in 100 ns units
    assert fields["ActiveProcessLimit"] == 8


def test_job_limits_without_kill_on_close():
    flags, fields = job_limits(cpu_seconds=1, kill_on_close=False)
    assert not flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    assert flags & JOB_OBJECT_LIMIT_PROCESS_TIME
    assert fields == {"PerProcessUserTimeLimit": 10_000_000}


def test_job_limits_only_memory():
    flags, fields = job_limits(memory_bytes=1)
    assert flags == 0x100 | 0x2000 | 0x400
    assert fields == {"ProcessMemoryLimit": 1}
    assert not flags & JOB_OBJECT_LIMIT_PROCESS_TIME
    assert not flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS


@pytest.mark.parametrize(
    "kwargs", [{"memory_bytes": 0}, {"cpu_seconds": 0}, {"max_processes": 0}, {"memory_bytes": -1}]
)
def test_job_limits_rejects_non_positive(kwargs):
    with pytest.raises(ValueError):
        job_limits(**kwargs)


def test_extended_limit_information_fills_structure():
    info = extended_limit_information(memory_bytes=1024, cpu_seconds=1.0, max_processes=3)
    basic = info.BasicLimitInformation
    assert basic.LimitFlags == 0x100 | 0x2 | 0x8 | 0x2000 | 0x400
    assert basic.PerProcessUserTimeLimit == 10_000_000
    assert basic.ActiveProcessLimit == 3
    assert info.ProcessMemoryLimit == 1024
    assert info.JobMemoryLimit == 0
    assert basic.PerJobUserTimeLimit == 0


# --------------------------------------------------------------------------- #
# ctypes structures
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not is_64bit, reason="documented sizes are for 64-bit Windows")
def test_structure_sizes_match_win64_documentation():
    assert ctypes.sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION) == 64
    assert ctypes.sizeof(IO_COUNTERS) == 48
    assert ctypes.sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION) == 144
    assert ctypes.sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS) == 4


def test_structure_field_types():
    basic = dict(JOBOBJECT_BASIC_LIMIT_INFORMATION._fields_)
    assert basic["PerProcessUserTimeLimit"] is ctypes.c_int64
    assert basic["PerJobUserTimeLimit"] is ctypes.c_int64
    assert basic["LimitFlags"] is ctypes.c_uint32
    assert basic["MinimumWorkingSetSize"] is ctypes.c_size_t
    assert basic["MaximumWorkingSetSize"] is ctypes.c_size_t
    assert basic["ActiveProcessLimit"] is ctypes.c_uint32
    assert basic["Affinity"] is ctypes.c_size_t
    assert basic["PriorityClass"] is ctypes.c_uint32
    assert basic["SchedulingClass"] is ctypes.c_uint32
    assert all(kind is ctypes.c_uint64 for _, kind in IO_COUNTERS._fields_)
    extended = dict(JOBOBJECT_EXTENDED_LIMIT_INFORMATION._fields_)
    assert extended["BasicLimitInformation"] is JOBOBJECT_BASIC_LIMIT_INFORMATION
    assert extended["IoInfo"] is IO_COUNTERS
    for name in ("ProcessMemoryLimit", "JobMemoryLimit", "PeakProcessMemoryUsed", "PeakJobMemoryUsed"):
        assert extended[name] is ctypes.c_size_t
    assert dict(JOBOBJECT_BASIC_UI_RESTRICTIONS._fields_)["UIRestrictionsClass"] is ctypes.c_uint32
    assert JOB_OBJECT_UILIMIT_ALL == 0xFF


def test_extended_structure_offsets():
    assert JOBOBJECT_EXTENDED_LIMIT_INFORMATION.BasicLimitInformation.offset == 0
    assert JOBOBJECT_EXTENDED_LIMIT_INFORMATION.IoInfo.offset == ctypes.sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION)
    assert JOBOBJECT_EXTENDED_LIMIT_INFORMATION.ProcessMemoryLimit.offset == ctypes.sizeof(
        JOBOBJECT_BASIC_LIMIT_INFORMATION
    ) + ctypes.sizeof(IO_COUNTERS)


# --------------------------------------------------------------------------- #
# JobObject and capabilities off-platform
# --------------------------------------------------------------------------- #

off_windows = pytest.mark.skipif(sys.platform == "win32", reason="off-platform behaviour")
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="requires Windows job objects")


@off_windows
def test_job_object_unavailable_off_windows():
    assert JobObject.available() is False
    assert JobObject.unavailable_reason()
    with pytest.raises(OSError):
        JobObject.create(memory_bytes=1024)


@off_windows
def test_capabilities_off_platform_do_not_crash():
    caps = WindowsBackend().capabilities()
    assert caps.name == WindowsBackend.name
    assert caps.platform == "win32"
    for name in (MEMORY_CAPPED, CPU_TIME_CAPPED, PROCESS_COUNT_CAPPED, KILLED_WITH_HOST):
        assert name not in caps.supported
        assert "job objects unavailable" in caps.unsupported[name]
    assert CLEAN_ENVIRONMENT in caps.supported


def test_capabilities_static_unsupported_reasons():
    caps = WindowsBackend().capabilities()
    assert caps.unsupported[FILESYSTEM_ALLOWLIST] == "requires AppContainer/ACL confinement; not implemented"
    assert caps.unsupported[NO_AMBIENT_NETWORK] == "requires AppContainer network capability model; not implemented"
    assert NO_NEW_PRIVILEGES in caps.unsupported
    assert REDUCED_KERNEL_SURFACE in caps.unsupported
    assert FILESYSTEM_ALLOWLIST not in caps.supported
    assert NO_AMBIENT_NETWORK not in caps.supported


def test_capabilities_are_cached():
    backend = WindowsBackend()
    assert backend.capabilities() is backend.capabilities()


def test_get_backend_win32_returns_windows_backend():
    assert isinstance(get_backend("win32"), WindowsBackend)


def test_select_backend_win32_refuses_filesystem_and_network():
    with pytest.raises(IsolationUnsupportedError) as info:
        select_backend(IsolationSpec.confined(), platform="win32")
    assert info.value.backend == WindowsBackend.name
    assert FILESYSTEM_ALLOWLIST in info.value.unmet
    assert NO_AMBIENT_NETWORK in info.value.unmet
    assert "AppContainer" in info.value.unmet[FILESYSTEM_ALLOWLIST]


@off_windows
def test_select_backend_win32_refuses_memory_off_platform():
    with pytest.raises(IsolationUnsupportedError) as info:
        select_backend(IsolationSpec(limits=ResourceLimits(memory="64M")), platform="win32")
    assert MEMORY_CAPPED in info.value.unmet
    assert "job objects unavailable" in info.value.unmet[MEMORY_CAPPED]


# --------------------------------------------------------------------------- #
# plan (pure)
# --------------------------------------------------------------------------- #


def _windows_capable(monkeypatch):
    """Pretend the job object API is available so plan() can be exercised anywhere."""
    monkeypatch.setattr(JobObject, "available", staticmethod(lambda: True))


def test_plan_shape(monkeypatch, tmp_path):
    _windows_capable(monkeypatch)
    session, worker = _session(tmp_path)
    spec = IsolationSpec(
        limits=ResourceLimits(memory="256M", cpu_seconds=5, max_processes=4, wall_time_seconds=30),
        env=EnvPolicy(mode="clean"),
    )
    plan = WindowsBackend().plan(spec, python=sys.executable, worker_path=worker, session_dir=session)
    assert plan.argv == [sys.executable, "-I", "-u", worker]
    assert plan.popen_kwargs == {"creationflags": CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW}
    assert plan.cwd == os.path.join(session, "work")
    assert plan.policy["chdir"] == os.path.join(session, "work")
    assert plan.policy["rlimits"] == {}
    assert plan.policy["landlock"] is None
    assert plan.policy["unshare_net"] is None
    assert plan.policy["no_new_privs"] is None
    assert plan.policy["seccomp"] is None
    assert plan.policy["die_with_parent"] is True
    assert plan.required_applied == ()
    assert plan.state["limits"] == {"memory_bytes": 256 * 1024**2, "cpu_seconds": 5, "max_processes": 4}
    assert plan.env["TEMP"] == os.path.join(session, "tmp")
    assert plan.env["TMP"] == os.path.join(session, "tmp")
    assert plan.env["PYTHONDONTWRITEBYTECODE"] == "1"
    report = plan.report
    assert report.backend == WindowsBackend.name
    assert report.platform == "win32"
    assert report.missing == frozenset()
    assert report.guarantees[MEMORY_CAPPED] == "job object ProcessMemoryLimit"
    assert report.guarantees[CPU_TIME_CAPPED] == "job object PerProcessUserTimeLimit"
    assert report.guarantees[PROCESS_COUNT_CAPPED] == "job object ActiveProcessLimit"
    assert report.guarantees[KILLED_WITH_HOST] == "job object KILL_ON_JOB_CLOSE"
    assert CLEAN_ENVIRONMENT in report.guarantees


def test_plan_inherit_env_keeps_host_variables(monkeypatch, tmp_path):
    _windows_capable(monkeypatch)
    monkeypatch.setenv("DSPY_INTERP_HOST_MARKER", "1")
    session, worker = _session(tmp_path)
    plan = WindowsBackend().plan(IsolationSpec(), python=sys.executable, worker_path=worker, session_dir=session)
    assert plan.argv == [sys.executable, "-u", worker]
    assert plan.env["DSPY_INTERP_HOST_MARKER"] == "1"
    assert plan.state["limits"] == {"memory_bytes": None, "cpu_seconds": None, "max_processes": None}


def test_plan_refuses_filesystem_allowlist(monkeypatch, tmp_path):
    _windows_capable(monkeypatch)
    session, worker = _session(tmp_path)
    with pytest.raises(IsolationUnsupportedError) as info:
        WindowsBackend().plan(IsolationSpec.confined(), python=sys.executable, worker_path=worker, session_dir=session)
    assert FILESYSTEM_ALLOWLIST in info.value.unmet


def test_attach_stores_job_and_kill_terminates(monkeypatch):
    events = []

    class FakeJob:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def assign(self, process):
            events.append(("assign", process.pid))

        def terminate(self, exit_code=1):
            events.append(("terminate", exit_code))

        def close(self):
            events.append("close")

    monkeypatch.setattr(JobObject, "create", classmethod(lambda cls, **kwargs: FakeJob(**kwargs)))

    class FakeProcess:
        pid = 77
        _handle = 12345

        def kill(self):
            events.append("kill")

    plan = LaunchPlan(
        argv=[],
        env={},
        cwd=None,
        policy={},
        report=None,
        state={"limits": {"memory_bytes": 4096, "cpu_seconds": 2.0, "max_processes": 3}},
    )
    backend = WindowsBackend()
    process = FakeProcess()
    backend.attach(process, plan)
    job = plan.state["job"]
    assert isinstance(job, FakeJob)
    assert job.kwargs == {
        "memory_bytes": 4096,
        "cpu_seconds": 2.0,
        "max_processes": 3,
        "kill_on_close": True,
        "ui_restrictions": True,
    }
    assert events == [("assign", 77)]
    backend.kill(process, plan)
    assert events[1:] == [("terminate", 1), "kill", "close"]


def test_attach_closes_job_when_assign_fails(monkeypatch):
    events = []

    class FakeJob:
        def assign(self, process):
            raise OSError("assign failed")

        def close(self):
            events.append("close")

    monkeypatch.setattr(JobObject, "create", classmethod(lambda cls, **kwargs: FakeJob()))
    plan = LaunchPlan(argv=[], env={}, cwd=None, policy={}, report=None)
    with pytest.raises(OSError):
        WindowsBackend().attach(object(), plan)
    assert events == ["close"]
    assert "job" not in plan.state


def test_kill_without_job_only_kills_process():
    events = []

    class FakeProcess:
        def kill(self):
            events.append("kill")

    WindowsBackend().kill(FakeProcess(), LaunchPlan(argv=[], env={}, cwd=None, policy={}, report=None))
    assert events == ["kill"]


# --------------------------------------------------------------------------- #
# Live (Windows only)
# --------------------------------------------------------------------------- #


@windows_only
def test_live_job_object_available():
    assert JobObject.available() is True
    caps = WindowsBackend().capabilities()
    assert MEMORY_CAPPED in caps.supported
    assert KILLED_WITH_HOST in caps.supported


@windows_only
def test_live_job_object_create_assign_terminate():
    job = JobObject.create(memory_bytes=256 * 1024**2, cpu_seconds=30, max_processes=4)
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        creationflags=CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
    )
    try:
        job.assign(process)
        job.terminate(1)
        assert process.wait(timeout=10) == 1
    finally:
        try:
            process.kill()
        except OSError:
            pass
        job.close()


@windows_only
def test_live_process_limit_blocks_children():
    from dspy import CodeExecutionError

    from dspy_interpreters import LocalInterpreter

    spec = IsolationSpec(limits=ResourceLimits(max_processes=1, wall_time_seconds=60))
    interpreter = LocalInterpreter(mode="subprocess", isolation=spec)
    interpreter.start()
    try:
        assert interpreter.execute("1 + 1") == 2
        with pytest.raises(CodeExecutionError):
            interpreter.execute("import subprocess, sys; subprocess.run([sys.executable, '-c', 'pass'], check=True)")
        assert interpreter.isolation_report is not None
        assert PROCESS_COUNT_CAPPED in interpreter.isolation_report.guarantees
    finally:
        interpreter.shutdown()
