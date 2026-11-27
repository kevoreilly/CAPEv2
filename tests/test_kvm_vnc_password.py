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

    assert sentinel not in str(exc_info.value)
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

    multi.bind_vnc_task("vm-kvm", 7)
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

    # Non-VNC sub-machinery and unknown labels must safely no-op.
    assert multi.get_vnc_password("vm-other") is None
    assert multi.get_vnc_password("missing") is None
    multi.bind_vnc_task("vm-other", 8)
    multi.store_vnc_port("vm-other", 8)
    multi.clear_vnc_password("vm-other")
    multi.unbind_vnc_task("vm-other")


def test_guac_views_supports_kvmremote_and_refreshes_expired_direct_vnc_snapshot():
    from importlib import import_module

    guac_views = import_module("guac.views")
    assert "kvmremote" in guac_views.machinery_available

    fake_libvirt = _make_fake_libvirt()
    expired_xml = (
        "<domain><devices>"
        "<graphics type='vnc' port='5901' passwd='placeholder' passwdValidTo='1970-01-01T00:00:01'/>"
        "</devices></domain>"
    )
    vm_expired = _FakeDomain(expired_xml)
    guac_views._refresh_direct_vnc_password_if_expired(vm_expired, fake_libvirt, "adminpwd")
    assert len(vm_expired.updated_devices) == 1
    elem = ET.fromstring(vm_expired.updated_devices[0][0])
    assert elem.get("passwd") == "adminpwd"
    assert "passwdValidTo" not in elem.attrib

    normal_vm = _FakeDomain("<domain><devices><graphics type='vnc' port='5901' passwd='static'/></devices></domain>")
    guac_views._refresh_direct_vnc_password_if_expired(normal_vm, fake_libvirt, "adminpwd")
    assert normal_vm.updated_devices == []


@pytest.mark.parametrize(
    "enabled, auth_only, authenticated, task_status, expected_status, expect_password",
    [
        pytest.param(False, True, True, TASK_RUNNING, 403, False, id="disabled-by-default"),
        pytest.param(True, True, False, TASK_RUNNING, 401, False, id="auth-required-rejects-anon"),
        pytest.param(True, True, True, TASK_RUNNING, 200, True, id="authenticated-running-returns-password"),
        pytest.param(True, False, False, TASK_RUNNING, 200, True, id="explicit-unauth-allowed-when-configured"),
        pytest.param(True, True, True, TASK_FAILED_ANALYSIS, 404, False, id="non-running-task-returns-404"),
    ],
)
def test_apiv2_tasks_vnc_endpoint_gating(
    db: _Database,
    monkeypatch,
    enabled,
    auth_only,
    authenticated,
    task_status,
    expected_status,
    expect_password,
):
    from importlib import import_module
    from django.test import RequestFactory

    apiv2_views = import_module("apiv2.views")

    tid = db.add_url("https://example.invalid/vnc-api", options="vnc_port=5906", machine="win10-1")
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
    req.user = SimpleNamespace(
        is_authenticated=authenticated,
        is_active=authenticated,
        id=7 if authenticated else None,
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

