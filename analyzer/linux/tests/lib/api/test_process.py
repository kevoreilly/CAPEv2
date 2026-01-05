from unittest.mock import Mock, patch, mock_open, PropertyMock
from lib.api.process import Process
import base64

import pytest

proc_status = """Name:	test-process
Umask:	0002
State:	R (running)
Tgid:	42
Ngid:	0
Pid:	42
PPid:	24"""

@pytest.fixture
def os_path_exists(monkeypatch):
    monkeypatch.setattr("os.path.exists", Mock(return_value=True))
    yield

@pytest.fixture
def os_path_not_exists(monkeypatch):
    monkeypatch.setattr("os.path.exists", Mock(return_value=False))
    yield

@pytest.fixture
def fake_proc_status_file(monkeypatch):
    monkeypatch.setattr("builtins.open", mock_open(read_data=proc_status))
    yield

ARGS = {
    "pid": 42
}

def test_init():
    """Initialize Process instances using both args and kwargs"""
    kw_args_instance = Process(**ARGS)
    assert kw_args_instance.pid ==  ARGS["pid"]
    args_instance = Process(*ARGS.values())
    assert args_instance.pid ==  ARGS["pid"]

@pytest.mark.usefixtures("os_path_exists")
def test_proc_alive_states():
    for state in [
        "State:	R (running)",
        "State:	S (sleeping)",
        "State:	D (waiting)",
        "State:	T (stopped)",
        "State:	t (trace stopped)",
        "State:	W (paging)",
        "State:	W (waking)",
        "State:	P (parked)",
    ]:
        state_file_content = proc_status.replace("State:	R (running)", state)
        with patch("builtins.open", mock_open(read_data=state_file_content)):
            process = Process(**ARGS)
            assert process.is_alive()

@pytest.mark.usefixtures("os_path_exists")
def test_proc_dead_states():
    for state in [
        "State:	Z (zombie)",
    ]:
        state_file_content = proc_status.replace("State:	R (running)", state)
        with patch("builtins.open", mock_open(read_data=state_file_content)):
            process = Process(**ARGS)
            alive = process.is_alive()
            assert not alive

@pytest.mark.usefixtures("os_path_not_exists")
def test_proc_file_not_exists():
    process = Process(**ARGS)
    assert not process.is_alive()

@pytest.mark.usefixtures("os_path_exists")
def test_proc_file_corrupt():
    corrupt_status = base64.b64encode(proc_status.encode("utf-8")).decode("utf-8")
    with patch("builtins.open", mock_open(read_data=corrupt_status)):
        process = Process(**ARGS)
        assert not process.is_alive()

@pytest.mark.usefixtures("os_path_exists", "fake_proc_status_file")
def test_get_ppid():
    process = Process(**ARGS)
    assert 24 == process.get_parent_pid()

@patch("builtins.open", side_effect=FileNotFoundError)
def test_get_ppid_file_not_exists(bopen):
    process = Process(**ARGS)
    assert process.get_parent_pid() is None

@patch("subprocess.Popen")
def test_execute(popen):
    process = Process(**ARGS)
    type(popen.return_value).pid = PropertyMock(return_value=ARGS["pid"])
    assert process.execute(["echo", "this is a test message"])
    assert ARGS["pid"] ==  process.pid
    assert popen.called
