import logging
import string
import threading
from contextlib import nullcontext
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest

import lib.cuckoo.common.abstracts as abstracts
from lib.cuckoo.common.abstracts import LibVirtMachinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.core.data.task import TASK_FAILED_ANALYSIS, TASK_RECOVERED, TASK_RUNNING
from lib.cuckoo.core.database import _Database
from modules.machinery.kvm import KVM
from modules.machinery.kvmremote import KVMRemote


class _FakeLibvirtError(Exception):
    pass


def _make_fake_libvirt():
    return SimpleNamespace(
        libvirtError=_FakeLibvirtError,
        VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED=2,
        VIR_DOMAIN_XML_SECURE=1,
        VIR_DOMAIN_AFFECT_LIVE=1,
    )


class _FakeSnapshot:
    def __init__(self, name="ready"):
        self._name = name

    def getName(self):
        return self._name


class _FakeDomain:
    def __init__(
        self,
        xml_desc,
        *,
        snapshot_names=("ready",),
        xml_error=None,
        update_error=None,
        resume_error=None,
        destroy_error=None,
        active=True,
    ):
        self._xml_desc = xml_desc
        self._snapshot_names = list(snapshot_names)
        self._xml_error = xml_error
        self._update_error = update_error
        self._resume_error = resume_error
        self._destroy_error = destroy_error
        self._active = active
        self.events = []
        self.revert_calls = []
        self.xml_flags = []
        self.updated_devices = []
        self.resume_count = 0
        self.destroy_count = 0

    def snapshotListNames(self, flags=0):
        return list(self._snapshot_names)

    def snapshotLookupByName(self, name, flags=0):
        return _FakeSnapshot(name)

    def revertToSnapshot(self, snapshot, flags=0):
        self.events.append(("revert", flags))
        self.revert_calls.append((snapshot.getName(), flags))

    def XMLDesc(self, flags=0):
        self.xml_flags.append(flags)
        if self._xml_error is not None:
            raise self._xml_error
        return self._xml_desc

    def updateDeviceFlags(self, xml, flags=0):
        self.events.append(("update_device", flags))
        self.updated_devices.append((xml, flags))
        if self._update_error is not None:
            raise self._update_error

    def resume(self):
        self.events.append(("resume",))
        self.resume_count += 1
        if self._resume_error is not None:
            raise self._resume_error

    def isActive(self):
        return self._active

    def destroy(self):
        self.events.append(("destroy",))
        self.destroy_count += 1
        if self._destroy_error is not None:
            raise self._destroy_error
        self._active = False


class _FakeConn:
    def __init__(self, vm):
        self._vm = vm

    def lookupByName(self, label):
        return self._vm


class _FakeDB:
    def __init__(self, snapshot="ready"):
        self._snapshot = snapshot
        self.vnc_ports = []
        self.vnc_passwords = []

    def transaction(self):
        return nullcontext()

    def view_machine_by_label(self, label):
        return SimpleNamespace(label=label, snapshot=self._snapshot)

    def set_vnc_port(self, task_id, port):
        self.vnc_ports.append((task_id, port))

    def set_vnc_password(self, task_id, password):
        self.vnc_passwords.append((task_id, password))

    def clear_vnc_password(self, task_id):
        self.vnc_passwords.append(("clear", task_id))


def _make_machinery(cls, *, vnc_per_task_password=False, vm=None, db=None):
    obj = cls.__new__(cls)
    obj.conn = None
    obj.conn_lock = threading.Lock()
    obj._vnc_passwords = {}
    obj._vnc_passwords_lock = threading.Lock()
    section = {"vnc_per_task_password": vnc_per_task_password}
    obj.options = SimpleNamespace(**{cls.module_name: section})
    obj.db = db if db is not None else _FakeDB()
    if vm is not None:
        obj._status = lambda label: obj.POWEROFF
        obj._connect = lambda label: _FakeConn(vm)
        obj._lookup = lambda label: vm
        obj._wait_status = lambda label, state: vm.events.append(("wait_status", state))
    return obj


@pytest.mark.parametrize(
    "raw_value, expected",
    [
        pytest.param(True, True, id="bool-true"),
        pytest.param(False, False, id="bool-false"),
        pytest.param(1, True, id="int-1"),
        pytest.param(0, False, id="int-0"),
        pytest.param("yes", True, id="str-yes"),
        pytest.param("YES", True, id="str-YES"),
        pytest.param("true", True, id="str-true"),
        pytest.param("on", True, id="str-on"),
        pytest.param("1", True, id="str-1"),
        pytest.param("no", False, id="str-no"),
        pytest.param("false", False, id="str-false"),
        pytest.param("0", False, id="str-0"),
        pytest.param("", False, id="str-empty"),
        pytest.param(None, False, id="none"),
    ],
)
def test_vnc_per_task_password_enabled_parsing(raw_value, expected):
    machinery = _make_machinery(KVM, vnc_per_task_password=raw_value)
    assert machinery._vnc_per_task_password_enabled() is expected


def test_vnc_per_task_password_enabled_missing_section_defaults_false():
    obj = KVM.__new__(KVM)
    obj.options = SimpleNamespace()
    assert obj._vnc_per_task_password_enabled() is False


def test_default_configs_disable_vnc_per_task_password():
    assert Config("kvm").kvm.vnc_per_task_password is False
    assert Config("kvmremote").kvmremote.vnc_per_task_password is False


def test_generate_vnc_password_format_and_uniqueness():
    allowed = set(string.ascii_letters + string.digits)
    passwords = [LibVirtMachinery._generate_vnc_password() for _ in range(64)]
    for pwd in passwords:
        assert len(pwd) == LibVirtMachinery.VNC_PASSWORD_LENGTH == 8
        assert set(pwd) <= allowed
    assert len(set(passwords)) == len(passwords)


def test_libvirt_start_disabled_keeps_legacy_revert_flow(monkeypatch):
    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    vm = _FakeDomain("<domain><devices><graphics type='vnc' port='5901' passwd='old'/></devices></domain>")
    machinery = _make_machinery(KVM, vnc_per_task_password=False, vm=vm)
    machinery._set_vnc_password("vm1", "stale123")

    LibVirtMachinery.start(machinery, "vm1")

    assert vm.revert_calls == [("ready", 0)]
    assert vm.updated_devices == []
    assert vm.resume_count == 0
    assert vm.destroy_count == 0
    assert machinery.get_vnc_password("vm1") is None


@pytest.mark.parametrize(
    "domain_xml, expected_attrs, expected_listen_addr",
    [
        pytest.param(
            "<domain><devices>"
            "<graphics type='vnc' port='5902' autoport='yes' listen='127.0.0.1' "
            "passwd='placeholder' passwdValidTo='1970-01-01T00:00:01'>"
            "<listen type='address' address='127.0.0.1'/>"
            "</graphics>"
            "</devices></domain>",
            {"type": "vnc", "port": "5902", "autoport": "yes", "listen": "127.0.0.1"},
            "127.0.0.1",
            id="tcp-with-expired-placeholder-and-listen",
        ),
        pytest.param(
            "<domain><devices>"
            "<graphics type='vnc' socket='/var/run/libvirt/qemu/vm1.vnc' passwd='old'/>"
            "</devices></domain>",
            {"type": "vnc", "socket": "/var/run/libvirt/qemu/vm1.vnc"},
            None,
            id="unix-socket-vnc",
        ),
    ],
)
def test_libvirt_start_enabled_rotates_password_while_paused(
    monkeypatch, domain_xml, expected_attrs, expected_listen_addr
):
    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    vm = _FakeDomain(domain_xml)
    machinery = _make_machinery(KVM, vnc_per_task_password=True, vm=vm)

    LibVirtMachinery.start(machinery, "vm1")

    password = machinery.get_vnc_password("vm1")
    assert password is not None
    assert len(password) == 8
    assert vm.revert_calls == [("ready", fake_libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)]
    assert vm.xml_flags == [fake_libvirt.VIR_DOMAIN_XML_SECURE]
    assert len(vm.updated_devices) == 1
    assert vm.resume_count == 1
    assert vm.destroy_count == 0
    assert vm.events == [
        ("revert", fake_libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED),
        ("update_device", fake_libvirt.VIR_DOMAIN_AFFECT_LIVE),
        ("resume",),
        ("wait_status", LibVirtMachinery.RUNNING),
    ]

    updated_xml, update_flags = vm.updated_devices[0]
    assert update_flags == fake_libvirt.VIR_DOMAIN_AFFECT_LIVE
    elem = ET.fromstring(updated_xml)
    assert elem.tag == "graphics"
    assert elem.get("passwd") == password
    assert "passwdValidTo" not in elem.attrib
    for key, value in expected_attrs.items():
        assert elem.get(key) == value
    if expected_listen_addr is not None:
        listen = elem.find("listen")
        assert listen is not None
        assert listen.get("address") == expected_listen_addr


def test_libvirt_consecutive_starts_generate_distinct_passwords(monkeypatch):
    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    domain_xml = "<domain><devices><graphics type='vnc' port='5901' passwd='old'/></devices></domain>"
    vm = _FakeDomain(domain_xml)
    machinery = _make_machinery(KVM, vnc_per_task_password=True, vm=vm)

    LibVirtMachinery.start(machinery, "vm1")
    first = machinery.get_vnc_password("vm1")
    LibVirtMachinery.start(machinery, "vm1")
    second = machinery.get_vnc_password("vm1")

    assert first and second and first != second


@pytest.mark.parametrize(
    "vm_kwargs, wait_error, match_pattern",
    [
        pytest.param(
            {"xml_desc": "<domain><devices/></domain>"},
            None,
            "No VNC graphics device found",
            id="missing-vnc-graphics",
        ),
        pytest.param(
            {"xml_desc": "", "xml_error": _FakeLibvirtError("xml lookup failed")},
            None,
            "Unable to read domain XML",
            id="xmldesc-libvirt-error",
        ),
        pytest.param(
            {
                "xml_desc": "<domain><devices><graphics type='vnc' port='5901'/></devices></domain>",
                "update_error": _FakeLibvirtError("Password authentication is not enabled"),
            },
            None,
            "Unable to set per-task VNC password",
            id="update-device-auth-not-enabled",
        ),
        pytest.param(
            {
                "xml_desc": "<domain><devices><graphics type='vnc' port='5901' passwd='old'/></devices></domain>",
                "resume_error": _FakeLibvirtError("resume failed"),
            },
            None,
            "Unable to enforce per-task VNC password",
            id="resume-libvirt-error",
        ),
        pytest.param(
            {"xml_desc": "<domain><devices><graphics type='vnc' port='5901' passwd='old'/></devices></domain>"},
            CuckooMachineError("Timeout hit"),
            "Timeout hit",
            id="wait-status-timeout",
        ),
    ],
)
def test_libvirt_start_fails_closed_without_leaking_password(
    monkeypatch, caplog, vm_kwargs, wait_error, match_pattern
):
    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    sentinel_password = "Ab12Cd34"
    vm = _FakeDomain(**vm_kwargs)
    machinery = _make_machinery(KVM, vnc_per_task_password=True, vm=vm)
    monkeypatch.setattr(machinery, "_generate_vnc_password", lambda: sentinel_password)
    if wait_error is not None:

        def _fail_wait(label, state):
            raise wait_error

        machinery._wait_status = _fail_wait

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(CuckooMachineError, match=match_pattern) as exc_info:
            LibVirtMachinery.start(machinery, "vm1")

    assert vm.destroy_count == 1
    assert machinery.get_vnc_password("vm1") is None
    assert sentinel_password not in str(exc_info.value)
    assert sentinel_password not in caplog.text


@pytest.mark.parametrize(
    "status_value, destroy_error, expect_error",
    [
        pytest.param(LibVirtMachinery.RUNNING, None, False, id="normal-stop"),
        pytest.param(
            LibVirtMachinery.RUNNING,
            _FakeLibvirtError("Requested operation is not valid: domain is not running"),
            False,
            id="domain-not-running",
        ),
        pytest.param(LibVirtMachinery.POWEROFF, None, True, id="already-poweroff"),
    ],
)
def test_libvirt_stop_always_clears_vnc_password(monkeypatch, status_value, destroy_error, expect_error):
    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    vm = _FakeDomain("<domain/>", destroy_error=destroy_error)
    machinery = _make_machinery(KVM, vnc_per_task_password=True, vm=vm)
    machinery._status = lambda label: status_value
    machinery._set_vnc_password("vm1", "Xy98Zw76")

    if expect_error:
        with pytest.raises(CuckooMachineError):
            machinery.stop("vm1")
    else:
        machinery.stop("vm1")

    assert machinery.get_vnc_password("vm1") is None


@pytest.mark.parametrize(
    "machinery_cls, domain_xml, active_password, expected_ports, expected_passwords",
    [
        pytest.param(
            KVM,
            "<domain><devices><graphics type='vnc' port='5903' passwd='secret12'/></devices></domain>",
            "secret12",
            [(77, 5903)],
            [(77, "secret12")],
            id="kvm-port-and-password",
        ),
        pytest.param(
            KVMRemote,
            "<domain><devices><graphics type='vnc' port='5904' passwd='secret34'/></devices></domain>",
            "secret34",
            [(88, 5904)],
            [(88, "secret34")],
            id="kvmremote-port-and-password",
        ),
        pytest.param(
            KVM,
            "<domain><devices><graphics type='vnc' port='5905'/></devices></domain>",
            None,
            [(99, 5905)],
            [],
            id="kvm-port-only-when-disabled",
        ),
        pytest.param(
            KVM,
            "<domain><devices><graphics type='vnc' socket='/tmp/vm1.vnc' passwd='sock1234'/></devices></domain>",
            "sock1234",
            [],
            [(101, "sock1234")],
            id="kvm-unix-socket-still-persists-password",
        ),
    ],
)
def test_store_vnc_port_persists_port_and_password(
    machinery_cls, domain_xml, active_password, expected_ports, expected_passwords
):
    db = _FakeDB()
    vm = _FakeDomain(domain_xml)
    machinery = _make_machinery(machinery_cls, vnc_per_task_password=bool(active_password), vm=vm, db=db)
    if active_password:
        machinery._set_vnc_password("vm1", active_password)

    task_id = expected_ports[0][0] if expected_ports else expected_passwords[0][0]
    machinery.store_vnc_port("vm1", task_id)

    assert db.vnc_ports == expected_ports
    assert db.vnc_passwords == expected_passwords


@pytest.mark.parametrize(
    "reschedule_enabled",
    [
        pytest.param(False, id="mark-failed-analysis"),
        pytest.param(True, id="reschedule-running-task"),
    ],
)
def test_startup_init_tasks_scrubs_stale_vnc_password(db: _Database, monkeypatch, reschedule_enabled):
    import lib.cuckoo.core.startup as startup_mod

    tid = db.add_url("https://example.invalid/crash-recovery", attributes={"main_task_id": 555})
    db.set_status(tid, TASK_RUNNING)
    db.set_vnc_password(tid, "CrAsH123")
    assert db.view_task(tid).get_attribute("vnc_password") == "CrAsH123"

    monkeypatch.setattr(startup_mod, "Database", lambda: db)
    monkeypatch.setattr(startup_mod.cuckoo.cuckoo, "reschedule", reschedule_enabled, raising=False)

    startup_mod.init_tasks()

    reloaded = db.view_task(tid)
    assert reloaded.get_attribute("vnc_password") is None
    assert reloaded.get_attribute("main_task_id") == 555
    if reschedule_enabled:
        assert reloaded.status == TASK_RECOVERED
        pending_tasks = [t for t in db.list_tasks() if t.id != tid]
        assert len(pending_tasks) == 1
        assert pending_tasks[0].get_attribute("vnc_password") is None
        assert pending_tasks[0].get_attribute("main_task_id") == 555
    else:
        assert reloaded.status == TASK_FAILED_ANALYSIS


def test_analysisinfo_does_not_leak_vnc_password(monkeypatch):
    import modules.processing.analysisinfo as ai

    inst = ai.AnalysisInfo.__new__(ai.AnalysisInfo)
    inst.task = {
        "id": 1,
        "sample_id": 5,
        "options": "foo=bar",
        "package": "exe",
        "category": "file",
        "custom": "",
        "machine": "",
        "tlp": None,
        "route": None,
        "started_on": "-",
        "completed_on": "-",
        "attributes": {"vnc_password": "SecRet99", "effective_route": "none"},
    }
    inst.log_path = "/tmp/nonexistent_analysis.log"

    class _InfoDB:
        def view_task(self, *a, **k):
            return None

        def get_parent_sample_from_task(self, *a, **k):
            return None

        def get_source_url(self, sample_id=None):
            return ""

    monkeypatch.setattr(ai, "db", _InfoDB())

    info = inst.run()
    assert "vnc_password" not in info
    assert "vnc_password" not in info["options"]
    assert "SecRet99" not in str(info)


def test_libvirt_start_updates_all_vnc_graphics_devices(monkeypatch):
    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    domain_xml = (
        "<domain><devices>"
        "<graphics type='vnc' port='5901' passwd='old1' passwdValidTo='1970-01-01T00:00:01'/>"
        "<graphics type='spice' port='5930'/>"
        "<graphics type='vnc' socket='/tmp/vm1.vnc' passwd='old2'/>"
        "</devices></domain>"
    )
    vm = _FakeDomain(domain_xml)
    machinery = _make_machinery(KVM, vnc_per_task_password=True, vm=vm)

    LibVirtMachinery.start(machinery, "vm1")

    password = machinery.get_vnc_password("vm1")
    assert password is not None
    assert len(vm.updated_devices) == 2
    ports_or_sockets = []
    for updated_xml, flags in vm.updated_devices:
        assert flags == fake_libvirt.VIR_DOMAIN_AFFECT_LIVE
        elem = ET.fromstring(updated_xml)
        assert elem.get("type") == "vnc"
        assert elem.get("passwd") == password
        assert "passwdValidTo" not in elem.attrib
        ports_or_sockets.append(elem.get("port") or elem.get("socket"))
    assert ports_or_sockets == ["5901", "/tmp/vm1.vnc"]


def test_libvirt_start_persists_password_before_resume_and_clears_on_resume_failure(monkeypatch):
    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    domain_xml = "<domain><devices><graphics type='vnc' port='5901' passwd='old'/></devices></domain>"
    vm = _FakeDomain(domain_xml)
    db = _FakeDB()
    order = []

    orig_set = db.set_vnc_password
    orig_clear = db.clear_vnc_password
    orig_resume = vm.resume

    def tracked_set(tid, pwd):
        order.append(("db_set", tid, pwd))
        orig_set(tid, pwd)

    def tracked_clear(tid):
        order.append(("db_clear", tid))
        orig_clear(tid)

    def tracked_resume():
        order.append(("vm_resume",))
        orig_resume()

    db.set_vnc_password = tracked_set
    db.clear_vnc_password = tracked_clear
    vm.resume = tracked_resume

    machinery = _make_machinery(KVM, vnc_per_task_password=True, vm=vm, db=db)
    machinery.bind_vnc_task("vm1", 42)
    LibVirtMachinery.start(machinery, "vm1")
    machinery.unbind_vnc_task("vm1")

    pwd = machinery.get_vnc_password("vm1")
    assert order == [("db_set", 42, pwd), ("vm_resume",)]

    # Resume failure after DB persist must destroy VM and scrub DB password.
    order.clear()
    vm2 = _FakeDomain(domain_xml, resume_error=_FakeLibvirtError("resume failed"))
    vm2.resume = lambda: (order.append(("vm_resume_fail",)), (_ for _ in ()).throw(_FakeLibvirtError("resume failed")))
    machinery2 = _make_machinery(KVM, vnc_per_task_password=True, vm=vm2, db=db)
    machinery2.bind_vnc_task("vm1", 43)
    with pytest.raises(CuckooMachineError, match="Unable to enforce per-task VNC password"):
        LibVirtMachinery.start(machinery2, "vm1")
    assert vm2.destroy_count == 1
    assert order[0][0] == "db_set" and order[0][1] == 43
    assert order[1] == ("vm_resume_fail",)
    assert order[2] == ("db_clear", 43)


def test_libvirt_start_fails_closed_when_revert_paused_constant_missing(monkeypatch):
    fake_libvirt = SimpleNamespace(
        libvirtError=_FakeLibvirtError,
        VIR_DOMAIN_XML_SECURE=1,
        VIR_DOMAIN_AFFECT_LIVE=1,
    )
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    vm = _FakeDomain("<domain><devices><graphics type='vnc' port='5901' passwd='old'/></devices></domain>")
    machinery = _make_machinery(KVM, vnc_per_task_password=True, vm=vm)

    with pytest.raises(CuckooMachineError, match="VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED"):
        LibVirtMachinery.start(machinery, "vm1")
    assert vm.revert_calls == []


def test_libvirt_start_redacts_password_echoed_in_libvirt_error_and_logs_destroy_failure(monkeypatch, caplog):
    import traceback

    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    sentinel = "LeAkMe99"
    vm = _FakeDomain(
        "<domain><devices><graphics type='vnc' port='5901' passwd='old'/></devices></domain>",
        update_error=_FakeLibvirtError(f"bad xml passwd='{sentinel}'"),
        destroy_error=_FakeLibvirtError(f"cannot destroy with {sentinel}"),
    )
    machinery = _make_machinery(KVM, vnc_per_task_password=True, vm=vm)
    monkeypatch.setattr(machinery, "_generate_vnc_password", lambda: sentinel)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(CuckooMachineError) as exc_info:
            LibVirtMachinery.start(machinery, "vm1")

    formatted_tb = "".join(traceback.format_exception(exc_info.value))
    assert sentinel not in str(exc_info.value)
    assert sentinel not in formatted_tb
    assert exc_info.value.__cause__ is None
    assert sentinel not in caplog.text
    assert "<redacted>" in str(exc_info.value)
    assert "Failed to destroy VM vm1" in caplog.text


def test_store_vnc_details_wraps_xmldesc_libvirt_error_as_machine_error(monkeypatch):
    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    vm = _FakeDomain("", xml_error=_FakeLibvirtError("ssh transport broken"))
    machinery = _make_machinery(KVMRemote, vnc_per_task_password=True, vm=vm)
    machinery._set_vnc_password("vm1", "Ab12Cd34")

    with pytest.raises(CuckooMachineError, match="Unable to read VNC details"):
        machinery.store_vnc_port("vm1", 55)


def test_libvirt_shutdown_clears_cached_vnc_passwords_and_bindings(monkeypatch):
    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    machinery = _make_machinery(KVM, vnc_per_task_password=True)
    machinery.machines = lambda: []
    machinery._set_vnc_password("vm1", "StAlE123")
    machinery.bind_vnc_task("vm1", 99)

    machinery.shutdown()

    assert machinery.get_vnc_password("vm1") is None
    assert machinery._get_bound_vnc_task("vm1") is None


def test_multi_machinery_forwards_vnc_helpers():
    from modules.machinery.multi import MultiMachinery

    calls = []

    class _SubKVM:
        def bind_vnc_task(self, label, task_id):
            calls.append(("bind", label, task_id))

        def unbind_vnc_task(self, label):
            calls.append(("unbind", label))

        def get_vnc_password(self, label):
            calls.append(("get", label))
            return "MuLtI123"

        def clear_vnc_password(self, label):
            calls.append(("clear", label))

        def store_vnc_port(self, label, task_id):
            calls.append(("store", label, task_id))

    class _SubOther:
        pass

    multi = MultiMachinery.__new__(MultiMachinery)
    multi._machine_labels = {"vm-kvm": "m1", "vm-other": "m2"}
    multi._machines = {"m1": {"machinery": "kvm"}, "m2": {"machinery": "other"}}
    multi._machineries = {"kvm": {"module": _SubKVM()}, "other": {"module": _SubOther()}}

    assert multi.bind_vnc_task("vm-kvm", 7) is True
    assert multi.get_vnc_password("vm-kvm") == "MuLtI123"
    multi.store_vnc_port("vm-kvm", 7)
    multi.clear_vnc_password("vm-kvm")
    multi.unbind_vnc_task("vm-kvm")
    assert calls == [
        ("bind", "vm-kvm", 7),
        ("get", "vm-kvm"),
        ("store", "vm-kvm", 7),
        ("clear", "vm-kvm"),
        ("unbind", "vm-kvm"),
    ]

    # Non-VNC sub-machinery and unknown labels must safely no-op and return False on bind.
    assert multi.get_vnc_password("vm-other") is None
    assert multi.get_vnc_password("missing") is None
    assert multi.bind_vnc_task("vm-other", 8) is False
    assert multi.bind_vnc_task("missing", 8) is False
    multi.store_vnc_port("vm-other", 8)
    multi.clear_vnc_password("vm-other")
    multi.unbind_vnc_task("vm-other")


def test_libvirt_start_fails_closed_when_db_set_vnc_password_returns_false(monkeypatch):
    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)

    vm = _FakeDomain("<domain><devices><graphics type='vnc' port='5901' passwd='old'/></devices></domain>")
    db = _FakeDB()
    db.set_vnc_password = lambda tid, pwd: False
    machinery = _make_machinery(KVM, vnc_per_task_password=True, vm=vm, db=db)
    machinery.bind_vnc_task("vm1", 404)

    with pytest.raises(CuckooMachineError, match="Unable to persist per-task VNC password"):
        LibVirtMachinery.start(machinery, "vm1")

    assert vm.resume_count == 0
    assert vm.destroy_count == 1
    assert machinery.get_vnc_password("vm1") is None


def test_libvirt_start_retries_transient_db_operational_error_on_pre_resume_persist(db: _Database, monkeypatch, caplog):
    from sqlalchemy.exc import OperationalError

    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)
    monkeypatch.setattr("lib.cuckoo.core.database.time.sleep", lambda _s: None)

    tid = db.add_url("https://example.invalid/retry-persist")
    db.set_status(tid, TASK_RUNNING)
    with db.session.begin():
        db.add_machine(
            name="vm1",
            label="vm1",
            arch="x64",
            ip="192.168.122.10",
            platform="windows",
            tags="x64",
            interface="virbr0",
            snapshot="ready",
            resultserver_ip="192.168.122.1",
            resultserver_port="2042",
            reserved=False,
        )

    attempts = 0
    real_set = db.set_vnc_password

    def flaky_set(task_id, password):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OperationalError(
                "UPDATE tasks SET attributes=? WHERE tasks.id = ?",
                (f'{{"vnc_password": "{password}"}}', task_id),
                Exception("connection dropped"),
            )
        return real_set(task_id, password)

    monkeypatch.setattr(db, "set_vnc_password", flaky_set)

    vm = _FakeDomain("<domain><devices><graphics type='vnc' port='5901' passwd='old'/></devices></domain>")
    machinery = _make_machinery(KVM, vnc_per_task_password=True, vm=vm, db=db)
    machinery.bind_vnc_task("vm1", tid)

    with caplog.at_level(logging.WARNING):
        LibVirtMachinery.start(machinery, "vm1")

    assert attempts == 2
    assert vm.resume_count == 1
    assert vm.destroy_count == 0
    pwd = machinery.get_vnc_password("vm1")
    assert pwd is not None
    assert pwd not in caplog.text
    assert "<redacted>" in caplog.text
    assert db.view_task(tid).get_attribute("vnc_password") == pwd


def test_store_vnc_port_retries_transient_db_operational_error_and_redacts_password(db: _Database, monkeypatch, caplog):
    from sqlalchemy.exc import OperationalError

    fake_libvirt = _make_fake_libvirt()
    monkeypatch.setattr(abstracts, "libvirt", fake_libvirt, raising=False)
    monkeypatch.setattr("lib.cuckoo.core.database.time.sleep", lambda _s: None)

    tid = db.add_url("https://example.invalid/store-vnc-retry")
    db.set_status(tid, TASK_RUNNING)

    attempts = 0
    real_set_port = db.set_vnc_port

    def flaky_set_port(task_id, port):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OperationalError(
                "UPDATE tasks SET options=? WHERE tasks.id = ?",
                ('{"vnc_password": "StOrE123"}', task_id),
                Exception("connection reset"),
            )
        return real_set_port(task_id, port)

    monkeypatch.setattr(db, "set_vnc_port", flaky_set_port)

    vm = _FakeDomain("<domain><devices><graphics type='vnc' port='5912' passwd='old'/></devices></domain>")
    machinery = _make_machinery(KVM, vnc_per_task_password=True, vm=vm, db=db)
    machinery._set_vnc_password("vm1", "StOrE123")

    with caplog.at_level(logging.WARNING):
        machinery.store_vnc_port("vm1", tid)

    assert attempts == 2
    assert "StOrE123" not in caplog.text
    assert "<redacted>" in caplog.text
    reloaded = db.view_task(tid)
    assert reloaded.get_attribute("vnc_password") == "StOrE123"
    assert "vnc_port=5912" in (reloaded.options or "")


@pytest.mark.parametrize(
    "start_mode",
    [
        pytest.param("snapshot", id="snapshot-mode"),
        pytest.param("dirty", id="dirty-mode"),
    ],
)
def test_guac_views_supports_kvmremote_and_refreshes_expired_direct_vnc_in_both_modes(monkeypatch, start_mode):
    import sys
    from importlib import import_module

    guac_views = import_module("guac.views")
    assert "kvmremote" in guac_views.machinery_available

    expired_xml = (
        "<domain><devices>"
        "<graphics type='vnc' port='5901' passwd='placeholder' passwdValidTo='1970-01-01T00:00:01'/>"
        "</devices></domain>"
    )
    vm_expired = _FakeDomain(expired_xml)
    created_calls = []

    def fake_create():
        vm_expired.events.append(("create", 0))
        created_calls.append(0)

    def fake_create_with_flags(flags=0):
        vm_expired.events.append(("create_with_flags", flags))
        created_calls.append(flags)

    vm_expired.create = fake_create
    vm_expired.createWithFlags = fake_create_with_flags

    class _DirectConn(_FakeConn):
        def close(self):
            pass

    fake_libvirt = _make_fake_libvirt()
    fake_libvirt.VIR_DOMAIN_START_PAUSED = 1
    fake_libvirt.open = lambda dsn: _DirectConn(vm_expired)

    monkeypatch.setitem(sys.modules, "libvirt", fake_libvirt)
    monkeypatch.setattr(guac_views.web_cfg.guacamole, "password", "adminpwd", raising=False)
    monkeypatch.setattr(guac_views, "_view_vm_machine", lambda _name: None)

    guac_views.bg_revert_and_start("qemu:///system", "vm1", start_mode, "ready")

    if start_mode == "snapshot":
        assert vm_expired.revert_calls == [("ready", fake_libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)]
        assert created_calls == []
        assert vm_expired.events == [
            ("revert", fake_libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED),
            ("update_device", fake_libvirt.VIR_DOMAIN_AFFECT_LIVE),
            ("resume",),
        ]
    else:
        assert vm_expired.revert_calls == []
        assert created_calls == [fake_libvirt.VIR_DOMAIN_START_PAUSED]
        assert vm_expired.events == [
            ("create_with_flags", fake_libvirt.VIR_DOMAIN_START_PAUSED),
            ("update_device", fake_libvirt.VIR_DOMAIN_AFFECT_LIVE),
            ("resume",),
        ]

    assert vm_expired.resume_count == 1
    assert len(vm_expired.updated_devices) == 1
    elem = ET.fromstring(vm_expired.updated_devices[0][0])
    assert elem.get("passwd") == "adminpwd"
    assert "passwdValidTo" not in elem.attrib

    normal_vm = _FakeDomain("<domain><devices><graphics type='vnc' port='5901' passwd='static'/></devices></domain>")
    guac_views._refresh_direct_vnc_password_if_expired(normal_vm, fake_libvirt, "adminpwd")
    assert normal_vm.updated_devices == []


@pytest.mark.parametrize(
    "token_auth_enabled, oidc_enabled, expect_api_key, expect_session_auth",
    [
        pytest.param(True, True, True, False, id="token-on-oidc-bool-true-drops-session-auth"),
        pytest.param("yes", "yes", True, False, id="token-on-oidc-str-yes-drops-session-auth"),
        pytest.param(True, False, True, True, id="token-on-oidc-bool-false-keeps-session-auth"),
        pytest.param("yes", "no", True, True, id="token-on-oidc-str-no-keeps-session-auth"),
        pytest.param(False, True, False, True, id="token-off-oidc-bool-true-keeps-session-auth"),
        pytest.param("no", "yes", False, True, id="token-off-oidc-str-yes-keeps-session-auth"),
        pytest.param(False, False, False, True, id="token-off-oidc-bool-false-keeps-session-auth"),
        pytest.param("no", "no", False, True, id="token-off-oidc-str-no-keeps-session-auth"),
    ],
)
def test_task_vnc_auth_classes_respects_oauth_oidc_section(
    token_auth_enabled, oidc_enabled, expect_api_key, expect_session_auth
):
    from importlib import import_module
    from apikey.authentication import ApiKeyAuthentication
    from rest_framework.authentication import SessionAuthentication

    apiv2_views = import_module("apiv2.views")
    fake_cfg = SimpleNamespace(oauth_oidc={"enabled": oidc_enabled})
    fake_api_cfg = SimpleNamespace(api={"token_auth_enabled": token_auth_enabled})
    classes = apiv2_views._task_vnc_auth_classes(fake_cfg, api_cfg=fake_api_cfg)
    assert (ApiKeyAuthentication in classes) is expect_api_key
    assert (SessionAuthentication in classes) is expect_session_auth


@pytest.mark.parametrize(
    "enabled, auth_only, user_kwargs, task_status, expected_status, expect_password",
    [
        pytest.param(False, True, {"is_authenticated": True, "id": 7}, TASK_RUNNING, 403, False, id="disabled-by-default"),
        pytest.param("no", True, {"is_authenticated": True, "id": 7}, TASK_RUNNING, 403, False, id="disabled-string-no"),
        pytest.param(True, True, {"is_authenticated": False, "id": None}, TASK_RUNNING, 401, False, id="auth-required-rejects-anon"),
        pytest.param(True, "yes", {"is_authenticated": False, "id": None}, TASK_RUNNING, 401, False, id="auth-only-string-yes"),
        pytest.param(True, True, {"is_authenticated": True, "id": 7}, TASK_RUNNING, 200, True, id="owner-running-returns-password"),
        pytest.param(
            True, True, {"is_authenticated": True, "id": 20}, TASK_RUNNING, 404, False, id="non-owner-denied-without-tenancy"
        ),
        pytest.param(
            True, True, {"is_authenticated": True, "id": 20, "is_staff": True}, TASK_RUNNING, 200, True, id="staff-allowed-without-tenancy"
        ),
        pytest.param(
            True,
            True,
            {"is_authenticated": True, "id": 20, "is_superuser": True},
            TASK_RUNNING,
            200,
            True,
            id="superuser-allowed-without-tenancy",
        ),
        pytest.param(
            "yes", "no", {"is_authenticated": False, "id": None}, TASK_RUNNING, 200, True, id="explicit-unauth-allowed-when-configured"
        ),
        pytest.param(True, True, {"is_authenticated": True, "id": 7}, TASK_FAILED_ANALYSIS, 404, False, id="non-running-task-returns-404"),
    ],
)
def test_apiv2_tasks_vnc_endpoint_gating(
    db: _Database,
    monkeypatch,
    enabled,
    auth_only,
    user_kwargs,
    task_status,
    expected_status,
    expect_password,
):
    from importlib import import_module
    from django.test import RequestFactory

    apiv2_views = import_module("apiv2.views")

    tid = db.add_url("https://example.invalid/vnc-api", options="vnc_port=5906", machine="requested-pool", user_id=7)
    with db.session.begin():
        machine = db.add_machine(
            name="m-win10",
            label="win10-1",
            arch="x64",
            ip="192.168.122.10",
            platform="windows",
            tags="x64",
            interface="virbr0",
            snapshot="ready",
            resultserver_ip="192.168.122.1",
            resultserver_port="2042",
            reserved=False,
        )
        task_obj = db.view_task(tid)
        db.create_guest(machine, "KVM", task_obj)
    db.set_status(tid, TASK_RUNNING)
    db.set_vnc_password(tid, "ApIv2Pw1")
    if task_status != TASK_RUNNING:
        db.set_status(tid, task_status)

    monkeypatch.setattr(apiv2_views, "db", db)
    monkeypatch.setattr(
        apiv2_views.apiconf,
        "taskvnc",
        {"enabled": enabled, "auth_only": auth_only},
        raising=False,
    )

    req = RequestFactory().get(f"/apiv2/tasks/vnc/{tid}/")
    is_auth = user_kwargs["is_authenticated"]
    req.user = SimpleNamespace(
        is_authenticated=is_auth,
        is_active=is_auth,
        id=user_kwargs["id"],
        is_staff=user_kwargs.get("is_staff", False),
        is_superuser=user_kwargs.get("is_superuser", False),
    )

    resp = apiv2_views.tasks_vnc(req, str(tid))
    assert resp.status_code == expected_status
    if expect_password:
        assert resp.data["error"] is False
        assert resp.data["data"]["task_id"] == tid
        assert resp.data["data"]["machine"] == "win10-1"
        assert resp.data["data"]["vnc_port"] == 5906
        assert resp.data["data"]["vnc_password"] == "ApIv2Pw1"
        assert resp["Cache-Control"] == "no-store"
    else:
        assert "ApIv2Pw1" not in str(resp.data)

    # Read-only tasks_view must never expose vnc_password even while the task is running.
    view_req = RequestFactory().get(f"/apiv2/tasks/view/{tid}/")
    view_resp = apiv2_views.tasks_view(view_req, str(tid))
    assert "ApIv2Pw1" not in str(view_resp.data)


def test_apiv2_tasks_vnc_does_not_query_requested_machine_and_resolves_distributed_worker(db: _Database, monkeypatch):
    from importlib import import_module
    from django.test import RequestFactory
    import lib.tenancy.storage.guac as storage_guac

    apiv2_views = import_module("apiv2.views")
    monkeypatch.setattr(apiv2_views, "db", db)
    monkeypatch.setattr(apiv2_views.apiconf, "taskvnc", {"enabled": True, "auth_only": True}, raising=False)

    # 1. Local task without bound guest must NOT fall back to requested task.machine or call local_vnc_port.
    tid_local = db.add_url("https://example.invalid/no-guest", machine="other-tenants-vm", user_id=7)
    db.set_status(tid_local, TASK_RUNNING)
    db.set_vnc_password(tid_local, "LoCaL123")

    local_port_calls = []
    monkeypatch.setattr(storage_guac, "worker_ip_for_task", lambda _tid: None)
    monkeypatch.setattr(storage_guac, "local_vnc_port", lambda label, **kw: local_port_calls.append(label) or 5999)

    req = RequestFactory().get(f"/apiv2/tasks/vnc/{tid_local}/")
    req.user = SimpleNamespace(is_authenticated=True, is_active=True, id=7, is_staff=False, is_superuser=False)
    resp = apiv2_views.tasks_vnc(req, str(tid_local))
    assert resp.status_code == 200
    assert resp.data["data"]["machine"] == ""
    assert resp.data["data"]["vnc_port"] is None
    assert resp.data["data"]["vnc_password"] == "LoCaL123"
    assert local_port_calls == []

    # 2. Distributed task resolves machine, port, and password from remote worker without reading control-plane attrs.
    monkeypatch.setattr(storage_guac, "worker_ip_for_task", lambda _tid: "10.20.30.40")
    monkeypatch.setattr(
        storage_guac,
        "worker_vnc_details_for_task",
        lambda _tid: ("worker-vm-9", 5909, "WoRkEr99"),
    )
    req2 = RequestFactory().get(f"/apiv2/tasks/vnc/{tid_local}/")
    req2.user = SimpleNamespace(is_authenticated=True, is_active=True, id=7, is_staff=False, is_superuser=False)
    resp2 = apiv2_views.tasks_vnc(req2, str(tid_local))
    assert resp2.status_code == 200
    assert resp2.data["data"] == {
        "task_id": tid_local,
        "machine": "worker-vm-9",
        "vnc_port": 5909,
        "vnc_password": "WoRkEr99",
    }
    assert resp2["Cache-Control"] == "no-store"


def test_apiv2_tasks_vnc_enforces_owner_check_when_tenancy_middleware_loaded_for_object_storage_only(
    db: _Database, monkeypatch
):
    from importlib import import_module
    from django.test import RequestFactory
    from lib.tenancy.policy import MTConfig, ViewerContext

    apiv2_views = import_module("apiv2.views")
    monkeypatch.setattr(apiv2_views, "db", db)
    monkeypatch.setattr(apiv2_views.apiconf, "taskvnc", {"enabled": True, "auth_only": True}, raising=False)
    monkeypatch.setattr(
        "lib.tenancy.policy.multitenancy_config",
        lambda: MTConfig(enabled=False, mode="shared", default_visibility="public", local_admins_manage_all_tenants=True),
    )

    tid = db.add_url("https://example.invalid/objstore-only", user_id=7)
    db.set_status(tid, TASK_RUNNING)
    db.set_vnc_password(tid, "ObJStOr1")

    # Simulate TenancyMiddleware loaded for [object_storage] with [multitenancy]=no and [web_auth]=no:
    # default_viewer_resolver() yields is_local_admin=True (see_all=True) even for a non-staff user.
    non_owner_req = RequestFactory().get(f"/apiv2/tasks/vnc/{tid}/")
    non_owner_req.user = SimpleNamespace(is_authenticated=True, is_active=True, id=20, is_staff=False, is_superuser=False)
    non_owner_req.viewer = ViewerContext(user_id=20, tenant_id=None, is_local_admin=True, is_authenticated=True)
    resp = apiv2_views.tasks_vnc(non_owner_req, str(tid))
    assert resp.status_code == 404
    assert "ObJStOr1" not in str(resp.data)

    # Owner and staff remain permitted.
    owner_req = RequestFactory().get(f"/apiv2/tasks/vnc/{tid}/")
    owner_req.user = SimpleNamespace(is_authenticated=True, is_active=True, id=7, is_staff=False, is_superuser=False)
    owner_req.viewer = ViewerContext(user_id=7, tenant_id=None, is_local_admin=True, is_authenticated=True)
    owner_resp = apiv2_views.tasks_vnc(owner_req, str(tid))
    assert owner_resp.status_code == 200
    assert owner_resp.data["data"]["vnc_password"] == "ObJStOr1"

    staff_req = RequestFactory().get(f"/apiv2/tasks/vnc/{tid}/")
    staff_req.user = SimpleNamespace(is_authenticated=True, is_active=True, id=20, is_staff=True, is_superuser=False)
    staff_req.viewer = ViewerContext(user_id=20, tenant_id=None, is_local_admin=True, is_authenticated=True)
    staff_resp = apiv2_views.tasks_vnc(staff_req, str(tid))
    assert staff_resp.status_code == 200
    assert staff_resp.data["data"]["vnc_password"] == "ObJStOr1"


def test_apiv2_tasks_vnc_prefers_live_libvirt_port_over_task_options(db: _Database, monkeypatch):
    from importlib import import_module
    from django.test import RequestFactory
    import lib.tenancy.storage.guac as storage_guac

    apiv2_views = import_module("apiv2.views")
    monkeypatch.setattr(apiv2_views, "db", db)
    monkeypatch.setattr(apiv2_views.apiconf, "taskvnc", {"enabled": True, "auth_only": True}, raising=False)
    monkeypatch.setattr(storage_guac, "worker_ip_for_task", lambda _tid: None)

    tid = db.add_url("https://example.invalid/live-port", options="vnc_port=5906", user_id=7)
    with db.session.begin():
        machine = db.add_machine(
            name="m-live",
            label="win10-live",
            arch="x64",
            ip="192.168.122.11",
            platform="windows",
            tags="x64",
            interface="virbr0",
            snapshot="ready",
            resultserver_ip="192.168.122.1",
            resultserver_port="2042",
            reserved=False,
        )
        db.create_guest(machine, "KVM", db.view_task(tid))
    db.set_status(tid, TASK_RUNNING)
    db.set_vnc_password(tid, "LiVePrt1")

    monkeypatch.setattr(storage_guac, "local_vnc_port", lambda label, **kw: 5915 if label == "win10-live" else None)
    req = RequestFactory().get(f"/apiv2/tasks/vnc/{tid}/")
    req.user = SimpleNamespace(is_authenticated=True, is_active=True, id=7, is_staff=False, is_superuser=False)
    resp = apiv2_views.tasks_vnc(req, str(tid))
    assert resp.status_code == 200
    assert resp.data["data"]["vnc_port"] == 5915

    # Falls back to task.options when live libvirt lookup returns None.
    monkeypatch.setattr(storage_guac, "local_vnc_port", lambda label, **kw: None)
    req2 = RequestFactory().get(f"/apiv2/tasks/vnc/{tid}/")
    req2.user = SimpleNamespace(is_authenticated=True, is_active=True, id=7, is_staff=False, is_superuser=False)
    resp2 = apiv2_views.tasks_vnc(req2, str(tid))
    assert resp2.status_code == 200
    assert resp2.data["data"]["vnc_port"] == 5906



