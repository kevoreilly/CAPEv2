import logging
from types import SimpleNamespace

from lib.cuckoo.common.exceptions import CuckooUnserviceableTaskError
from lib.cuckoo.core.data.task import TASK_FAILED_ANALYSIS
from lib.cuckoo.core.scheduler import Scheduler


def _make_tag(name: str):
    return SimpleNamespace(name=name)


def _make_machine(name="vm1", platform="windows", arch="x64", tags=(), locked=False, reserved=False):
    return SimpleNamespace(
        name=name,
        platform=platform,
        arch=arch,
        tags=[_make_tag(t) for t in tags],
        locked=locked,
        reserved=reserved,
    )


def test_unserviceable_task_logs_configured_pool_when_all_machines_locked(caplog):
    """When all VMs are locked, unserviceable diagnostics must still show configured pool
    capabilities (including arch, platform, tags, reserved count) as a plain dict, not an empty defaultdict."""
    task = SimpleNamespace(
        id=42,
        category="file",
        machine=None,
        platform="linux",
        package="msix",
        tags=[_make_tag("x64")],
    )
    machines = [
        _make_machine("vm1", platform="windows", arch="x64", tags=("win10", "x64"), locked=True, reserved=False),
        _make_machine("vm2", platform="windows", arch="x64", tags=("win10",), locked=True, reserved=True),
    ]
    failed = []
    list_machines_calls = []

    def _list_machines(include_reserved=False, **_kw):
        list_machines_calls.append(include_reserved)
        return machines if include_reserved else [m for m in machines if not m.reserved]

    sched = Scheduler.__new__(Scheduler)
    sched.cfg = SimpleNamespace(cuckoo=SimpleNamespace(fail_unserviceable=True))
    sched.db = SimpleNamespace(
        list_tasks=lambda **kw: [task] if kw.get("offset", 0) == 0 else [],
        list_machines=_list_machines,
        get_available_machines=lambda: [],
        set_status=lambda tid, status: failed.append((tid, status)),
        _package_vm_requires_check=lambda pkg: ["win10", "win11"] if pkg == "msix" else [],
    )
    sched.machinery_manager = SimpleNamespace(
        find_machine_to_service_task=lambda _t: (_ for _ in ()).throw(CuckooUnserviceableTaskError()),
    )

    with caplog.at_level(logging.INFO, logger="lib.cuckoo.core.scheduler"):
        chosen_task, chosen_machine = sched.find_pending_task_to_service()

    assert chosen_task is None
    assert chosen_machine is None
    assert failed == [(42, TASK_FAILED_ANALYSIS)]
    assert list_machines_calls == [True]
    assert "defaultdict" not in caplog.text
    assert "platform='linux'" in caplog.text
    assert "package='msix' (requires any of: win10, win11)" in caplog.text
    assert "tags='x64'" in caplog.text
    assert "Configured machines (2 total, 0 available, 1 reserved): {'win10': 2, 'windows': 2, 'x64': 2}" in caplog.text


def test_find_pending_task_skips_machine_stats_query_when_serviceable():
    """Avoid querying machine pool stats on normal ticks when no task raises CuckooUnserviceableTaskError."""
    task = SimpleNamespace(id=7, category="file", machine=None, platform="windows", package="", tags=[])
    vm = _make_machine("vm1")
    stats_queries = []

    sched = Scheduler.__new__(Scheduler)
    sched.cfg = SimpleNamespace(cuckoo=SimpleNamespace(fail_unserviceable=True))
    sched.db = SimpleNamespace(
        list_tasks=lambda **kw: [task] if kw.get("offset", 0) == 0 else [],
        list_machines=lambda **kw: stats_queries.append(kw) or [vm],
        get_available_machines=lambda: stats_queries.append("avail") or [vm],
        set_status=lambda _tid, _status: None,
    )
    sched.machinery_manager = SimpleNamespace(find_machine_to_service_task=lambda _t: vm)

    chosen_task, chosen_machine = sched.find_pending_task_to_service()
    assert chosen_task is task
    assert chosen_machine is vm
    assert stats_queries == []


def test_get_available_machine_stats_includes_arch_without_double_counting():
    machines = [
        _make_machine("vm1", platform="windows", arch="x64", tags=("win10", "x64")),
        _make_machine("vm2", platform="windows", arch="x86", tags=("win7",)),
    ]
    sched = Scheduler.__new__(Scheduler)
    sched.db = SimpleNamespace(
        get_available_machines=lambda: machines,
        list_machines=lambda **_kw: machines,
    )

    stats = sched.get_available_machine_stats()
    assert dict(stats) == {"windows": 2, "x64": 1, "x86": 1, "win10": 1, "win7": 1}
