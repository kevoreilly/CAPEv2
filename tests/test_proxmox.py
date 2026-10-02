import importlib
import sys
from types import ModuleType, SimpleNamespace
from typing import Generator

import pytest
from pytest_mock import MockerFixture
from requests.exceptions import RequestException


class FakeClock:
    """Deterministic clock for timeout-based retry tests."""

    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


@pytest.fixture
def proxmox_module(
    monkeypatch: pytest.MonkeyPatch,
    mocker: MockerFixture,
) -> Generator:
    """Import Proxmox machinery without requiring proxmoxer."""

    proxmoxer = ModuleType("proxmoxer")

    class ResourceException(Exception):
        """Minimal representation of proxmoxer's ResourceException."""

        def __init__(
            self,
            status_code,
            status_message,
            content,
            errors=None,
            exit_code=None,
        ):
            self.status_code = status_code
            self.status_message = status_message
            self.content = content
            self.errors = errors
            self.exit_code = exit_code
            super().__init__(f"{status_code} {status_message}: {content}")

    proxmoxer.ProxmoxAPI = mocker.Mock()
    proxmoxer.ResourceException = ResourceException

    monkeypatch.setitem(sys.modules, "proxmoxer", proxmoxer)
    sys.modules.pop("modules.machinery.proxmox", None)

    module = importlib.import_module("modules.machinery.proxmox")

    yield module

    sys.modules.pop("modules.machinery.proxmox", None)


def make_machinery(proxmox_module, timeout):
    machinery = proxmox_module.Proxmox.__new__(
        proxmox_module.Proxmox
    )
    machinery.timeout = timeout
    return machinery


def install_fake_clock(
    proxmox_module,
    mocker: MockerFixture,
):
    clock = FakeClock()

    mocker.patch.object(
        proxmox_module.time,
        "monotonic",
        clock.monotonic,
    )
    mocker.patch.object(
        proxmox_module.time,
        "sleep",
        clock.sleep,
    )

    return clock


def resource_error(
    proxmox_module,
    status_code,
    status_message,
    content,
):
    return proxmox_module.ResourceException(
        status_code,
        status_message,
        content,
    )


def test_find_vm_retries_resource_get_until_success(
    proxmox_module,
    mocker: MockerFixture,
):
    machinery = make_machinery(proxmox_module, timeout=10)
    clock = install_fake_clock(proxmox_module, mocker)

    machinery.options = SimpleNamespace(
        proxmox=SimpleNamespace(
            hostname="proxmox.example",
            username="test-user",
            password="test-password",
        )
    )

    proxmox = proxmox_module.ProxmoxAPI.return_value
    vm_proxy = mocker.Mock()

    class HypervisorProxy:
        def __getattr__(self, vmid):
            assert vmid == "101"
            return vm_proxy

    class NodeProxy:
        def __getattr__(self, vm_type):
            assert vm_type == "qemu"
            return HypervisorProxy()

    node_proxy = NodeProxy()
    proxmox.nodes.return_value = node_proxy

    proxmox.cluster.resources.get.side_effect = [
        resource_error(
            proxmox_module,
            400,
            "Bad Request",
            "request could not be processed",
        ),
        [
            {
                "name": "analysis-vm",
                "node": "node-a",
                "type": "qemu",
                "vmid": 101,
            }
        ],
    ]

    found_vm, found_node = machinery.find_vm("analysis-vm")

    assert found_vm is vm_proxy
    assert found_node is node_proxy
    assert proxmox.cluster.resources.get.call_count == 2
    assert clock.now < machinery.timeout


def test_find_snapshot_retries_request_get_until_success(
    proxmox_module,
    mocker: MockerFixture,
):
    machinery = make_machinery(proxmox_module, timeout=10)
    clock = install_fake_clock(proxmox_module, mocker)

    machinery.db = mocker.Mock()
    machinery.db.view_machine_by_label.return_value.snapshot = None

    vm = mocker.Mock()
    vm.snapshot.get.side_effect = [
        RequestException("temporary transport failure"),
        [
            {"name": "current"},
            {"name": "older", "snaptime": 100},
            {"name": "newer", "snaptime": 200},
        ],
    ]

    snapshot = machinery.find_snapshot("analysis-vm", vm)

    assert snapshot == "newer"
    assert vm.snapshot.get.call_count == 2
    assert clock.now < machinery.timeout


def test_wait_for_task_retries_resource_get_until_success(
    proxmox_module,
    mocker: MockerFixture,
):
    machinery = make_machinery(proxmox_module, timeout=10)
    clock = install_fake_clock(proxmox_module, mocker)

    node = mocker.Mock()
    vm = mocker.Mock()

    completed_task = {
        "type": "qmrollback",
        "status": "stopped",
        "exitstatus": "OK",
    }

    node.tasks.return_value.status.get.side_effect = [
        resource_error(
            proxmox_module,
            400,
            "Bad Request",
            "request could not be processed",
        ),
        resource_error(
            proxmox_module,
            503,
            "Service Unavailable",
            "temporary API failure",
        ),
        completed_task,
    ]
    vm.status.current.get.return_value = {"status": "stopped"}

    task = machinery.wait_for_task(
        "UPID:test",
        "analysis-vm",
        vm,
        node,
    )

    assert task == completed_task
    assert node.tasks.return_value.status.get.call_count == 3
    assert clock.now < machinery.timeout


def test_wait_for_task_stops_retrying_get_at_timeout(
    proxmox_module,
    mocker: MockerFixture,
):
    machinery = make_machinery(proxmox_module, timeout=5)
    clock = install_fake_clock(proxmox_module, mocker)

    node = mocker.Mock()
    vm = mocker.Mock()

    node.tasks.return_value.status.get.side_effect = resource_error(
        proxmox_module,
        400,
        "Bad Request",
        "request could not be processed",
    )

    task = machinery.wait_for_task(
        "UPID:test",
        "analysis-vm",
        vm,
        node,
    )

    assert task is None
    assert clock.now >= machinery.timeout
    assert node.tasks.return_value.status.get.call_count > 1
    vm.status.current.get.assert_not_called()


def test_wait_for_task_retries_vm_status_get_until_success(
    proxmox_module,
    mocker: MockerFixture,
):
    machinery = make_machinery(proxmox_module, timeout=10)
    clock = install_fake_clock(proxmox_module, mocker)

    node = mocker.Mock()
    vm = mocker.Mock()

    completed_task = {
        "type": "qmrollback",
        "status": "stopped",
        "exitstatus": "OK",
    }

    node.tasks.return_value.status.get.return_value = completed_task
    vm.status.current.get.side_effect = [
        RequestException("temporary transport failure"),
        {"status": "stopped"},
    ]

    task = machinery.wait_for_task(
        "UPID:test",
        "analysis-vm",
        vm,
        node,
    )

    assert task == completed_task
    assert vm.status.current.get.call_count == 2
    assert clock.now < machinery.timeout


def test_start_retries_vm_status_get_until_success(
    proxmox_module,
    mocker: MockerFixture,
):
    machinery = make_machinery(proxmox_module, timeout=10)
    install_fake_clock(proxmox_module, mocker)

    vm = mocker.Mock()
    node = mocker.Mock()

    mocker.patch.object(machinery, "find_vm", return_value=(vm, node))
    mocker.patch.object(machinery, "rollback")

    vm.status.current.get.side_effect = [
        RequestException("temporary transport failure"),
        {"status": "running"},
    ]

    machinery.start("analysis-vm")

    assert vm.status.current.get.call_count == 2
    machinery.rollback.assert_called_once_with("analysis-vm", vm, node)
