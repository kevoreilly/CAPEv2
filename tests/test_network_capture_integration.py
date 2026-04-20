import sys
from types import ModuleType
from unittest.mock import mock_open, patch

import pytest

def _stub_module(name):
    module = ModuleType(name)
    sys.modules.setdefault(name, module)
    return module


gevent_mod = _stub_module("gevent")
gevent_mod.__path__ = []
gevent_pool_mod = _stub_module("gevent.pool")
gevent_server_mod = _stub_module("gevent.server")
gevent_socket_mod = _stub_module("gevent.socket")
gevent_thread_mod = _stub_module("gevent.thread")
gevent_mod.pool = gevent_pool_mod
gevent_mod.server = gevent_server_mod
gevent_mod.socket = gevent_socket_mod
gevent_mod.thread = gevent_thread_mod
gevent_server_mod.StreamServer = object
gevent_pool_mod.Pool = object

abstracts_mod = ModuleType("lib.cuckoo.common.abstracts")


class Processing:
    def __init__(self, results=None):
        self.results = results
        self.analysis_path = ""
        self.pcap_path = ""
        self.options = None

    def set_path(self, analysis_path):
        self.analysis_path = analysis_path
        self.pcap_path = f"{analysis_path}/dump.pcap"

    def set_options(self, options):
        self.options = options


class ProtocolHandler:
    def __init__(self, task_id, ctx, version=None):
        self.task_id = task_id
        self.handler = ctx
        self.version = version
        self.fd = None


abstracts_mod.Processing = Processing
abstracts_mod.ProtocolHandler = ProtocolHandler
sys.modules.setdefault("lib.cuckoo.common.abstracts", abstracts_mod)

objects_mod = ModuleType("lib.cuckoo.common.objects")


class File:
    def __init__(self, path):
        self.path = path

    def get_sha256(self):
        return "sha256"


objects_mod.File = File
sys.modules.setdefault("lib.cuckoo.common.objects", objects_mod)

log_mod = ModuleType("lib.cuckoo.core.log")
log_mod.task_log_start = lambda *args, **kwargs: None
log_mod.task_log_stop = lambda *args, **kwargs: None
log_mod.task_log_stop_force = lambda *args, **kwargs: None
sys.modules.setdefault("lib.cuckoo.core.log", log_mod)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.core.resultserver import FileUpload
from modules.processing import decryptpcap as decryptpcap_mod
from modules.processing.network_etw import AttributionIndex



class DummySock:
    def settimeout(self, _value):
        pass


class DummyContext:
    def __init__(self, storagepath, lines):
        self.storagepath = storagepath
        self.sock = DummySock()
        self._lines = list(lines)

    def read_newline(self):
        return self._lines.pop(0)

    def copy_to_fd(self, fd, _max_size=None):
        fd.write(b"payload")
        fd.flush()


def test_auxiliary_config_registers_network_etw():
    cfg = Config("auxiliary")

    assert hasattr(cfg.auxiliary_modules, "network_etw")


def test_processing_config_registers_decryptpcap_and_network_etw():
    cfg = Config("processing")

    assert cfg.get("decryptpcap").enabled is False
    assert cfg.get("network_etw").enabled is False


def test_resultserver_rejects_overwrite_for_unrelated_aux_files(tmp_path):
    ctx = DummyContext(str(tmp_path), [b"aux/DigiSig.json"])
    upload = FileUpload(task_id=7, ctx=ctx)
    upload.init()

    with pytest.raises(CuckooOperationalError, match="overwrite an existing file"):
        with patch("lib.cuckoo.core.resultserver.path_exists", return_value=True), patch(
            "lib.cuckoo.core.resultserver.open_exclusive", side_effect=OSError(17, "exists")
        ):
            upload.handle()


def test_resultserver_allows_overwrite_for_periodic_aux_logs(tmp_path):
    ctx = DummyContext(str(tmp_path), [b"aux/network_etw.json"])
    upload = FileUpload(task_id=7, ctx=ctx)
    upload.init()

    fake_fd = mock_open().return_value

    with patch("lib.cuckoo.core.resultserver.path_exists", return_value=True), patch(
        "lib.cuckoo.core.resultserver.open", mock_open()
    ) as patched_open:
        upload.handle()

    patched_open.assert_any_call(str(tmp_path / "aux/network_etw.json"), "wb")
    fake_fd.write.assert_not_called()


def test_pcap_selector_prefers_mixed_pcap_when_configured(tmp_path):
    mixed = tmp_path / "dump_mixed.pcap"
    mixed.write_bytes(b"x" * 32)

    selected = decryptpcap_mod.resolve_processing_pcap_path(
        analysis_path=str(tmp_path),
        default_pcap_path=str(tmp_path / "dump.pcap"),
        pcapsrc="mixed",
    )

    assert selected == str(mixed)


def test_pcap_selector_prefers_decrypted_pcap_when_configured(tmp_path):
    decrypted = tmp_path / "dump_decrypted.pcap"
    decrypted.write_bytes(b"x" * 32)

    selected = decryptpcap_mod.resolve_processing_pcap_path(
        analysis_path=str(tmp_path),
        default_pcap_path=str(tmp_path / "dump.pcap"),
        pcapsrc="decrypted",
    )

    assert selected == str(decrypted)


def test_attribution_index_backfills_process_names():
    idx = AttributionIndex()

    idx.add_connection(pid=42, dst_ip="8.8.8.8", dst_port=443, protocol="tcp", process_name="", source="kernel_etw")
    idx.add_pid_name(42, "powershell.exe")

    hit = idx.for_ip("8.8.8.8", dst_port=443)

    assert hit["process_name"] == "powershell.exe"
