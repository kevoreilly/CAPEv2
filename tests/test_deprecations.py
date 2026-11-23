import asyncio
import importlib
import io
import logging
import os
import stat
import sys
import warnings
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def test_procmon_log_parses_events_and_is_truthy(tmp_path):
    from modules.processing.procmon import ProcmonLog

    xml_path = tmp_path / "procmon.xml"
    xml_path.write_text(
        "<procmon><eventlist>"
        "<event><Process_Name>sample.exe</Process_Name><Operation>CreateFile</Operation></event>"
        "<event><Process_Name>sample.exe</Process_Name><Operation>RegOpenKey</Operation></event>"
        "</eventlist></procmon>",
        encoding="utf-8",
    )
    plog = ProcmonLog(str(xml_path))
    assert bool(plog) is True
    events = list(next(plog))
    assert events == [
        {"Process_Name": "sample.exe", "Operation": "CreateFile"},
        {"Process_Name": "sample.exe", "Operation": "RegOpenKey"},
    ]


def test_mongodb_fix_int2str_converts_nested_non_string_keys():
    from modules.reporting.mongodb import MongoDB

    reporter = object.__new__(MongoDB)
    payload = {1: "a", "nested": {2: "b", "list": [{3: "c"}]}}
    reporter.fix_int2str(payload)
    assert payload == {"1": "a", "nested": {"2": "b", "list": [{"3": "c"}]}}


def test_check_linux_dist_uses_freedesktop_os_release(monkeypatch, caplog):
    import platform

    from lib.cuckoo.core import startup

    monkeypatch.setattr(platform, "freedesktop_os_release", lambda: {"ID": "ubuntu", "VERSION_ID": "24.04"})
    with caplog.at_level(logging.INFO):
        startup.check_linux_dist()
    assert not caplog.records

    monkeypatch.setattr(platform, "freedesktop_os_release", lambda: {"ID": "debian", "VERSION_ID": "12"})
    with caplog.at_level(logging.INFO):
        startup.check_linux_dist()
    assert any("NOT supported Linux distribution" in r.getMessage() for r in caplog.records)

    caplog.clear()
    monkeypatch.setattr(platform, "freedesktop_os_release", MagicMock(side_effect=OSError("missing")))
    with caplog.at_level(logging.INFO):
        startup.check_linux_dist()
    assert not caplog.records


def test_behavior_process_log_bool():
    from modules.processing.behavior import ParseProcessLog

    opts_boost = SimpleNamespace(ram_boost=True, ram_mmap=False, analysis_call_limit=0)
    empty_log = ParseProcessLog("/nonexistent/path.bson", opts_boost)
    assert bool(empty_log) is False
    empty_log.api_call_cache = [{"api": "CreateFileW"}, None]
    assert bool(empty_log) is True

    opts_nobuf = SimpleNamespace(ram_boost=False, ram_mmap=False, analysis_call_limit=0)
    empty_nobuf = ParseProcessLog("/nonexistent/path.bson", opts_nobuf)
    assert bool(empty_nobuf) is False


def test_analysisinfo_and_debug_read_logs_without_deprecation_warning(tmp_path, monkeypatch):
    from modules.processing import analysisinfo, debug

    log_file = tmp_path / "analysis.log"
    log_file.write_text(
        'INFO: analysis package selected: "exe"\nINFO: Analysis timeout hit, terminating analysis\n',
        encoding="utf-8",
    )

    ai = analysisinfo.AnalysisInfo()
    ai.log_path = str(log_file)
    ai.task = {"package": ""}

    dbg = debug.Debug()
    dbg.log_path = str(log_file)
    dbg.task = {"id": 1}
    dbg.options = {"buffer": 8192}

    fake_db = MagicMock()
    fake_db.view_errors.return_value = []
    monkeypatch.setattr(debug, "Database", lambda: fake_db)

    with warnings.catch_warnings(record=True) as ws:
        warnings.simplefilter("always", DeprecationWarning)
        assert ai.had_timeout() is True
        assert ai.get_package() == "exe"
        res = dbg.run()

    assert "Analysis timeout hit" in res["log"]
    assert [w for w in ws if issubclass(w.category, DeprecationWarning)] == []


def test_parse_pe_get_icon_info_no_pillow_deprecation_warning(monkeypatch):
    import pefile
    from PIL import Image

    import lib.cuckoo.common.integrations.parse_pe as parse_pe

    ico_buf = io.BytesIO()
    Image.new("RGBA", (16, 16), (255, 0, 0, 255)).save(ico_buf, format="ICO")
    ico_bytes = ico_buf.getvalue()

    pe_helper = parse_pe.PortableExecutable("/tmp/fake.exe")

    fake_entry = MagicMock()
    fake_entry.id = 1
    fake_entry.directory.entries = [MagicMock(data=MagicMock(struct=MagicMock(OffsetToData=0, Size=16)))]

    fake_group_dir = MagicMock()
    fake_group_dir.id = pefile.RESOURCE_TYPE["RT_GROUP_ICON"]
    fake_group_dir.directory.entries = [fake_entry]

    fake_icon_dir = MagicMock()
    fake_icon_dir.id = pefile.RESOURCE_TYPE["RT_ICON"]
    fake_icon_dir.directory.entries = [fake_entry]

    fake_pe = MagicMock()
    fake_pe.DIRECTORY_ENTRY_RESOURCE.entries = [fake_group_dir, fake_icon_dir]
    fake_pe.get_memory_mapped_image.return_value = b"\x00" * 64

    fake_icon_meta = MagicMock(bWidth=16, bHeight=16, wBitCount=32, nID=1)
    fake_peicon = MagicMock()
    fake_peicon.icons = [fake_icon_meta]
    fake_peicon.get_icon_file.return_value = ico_bytes

    monkeypatch.setattr(parse_pe, "PEGroupIconDir", lambda data: fake_peicon)

    with warnings.catch_warnings(record=True) as ws:
        warnings.simplefilter("always", DeprecationWarning)
        icon, fullhash, simphash, dhash = pe_helper.get_icon_info(fake_pe)

    assert icon is not None
    assert fullhash is not None
    assert simphash is not None
    assert dhash is not None
    assert [w for w in ws if issubclass(w.category, DeprecationWarning)] == []


def test_abstracts_dns_uses_resolve_not_query(monkeypatch):
    import lib.cuckoo.common.abstracts as abstracts

    fake_resolver = MagicMock()
    fake_resolver.resolve.side_effect = [
        [SimpleNamespace(address="1.2.3.4")],
        [SimpleNamespace(target="host.example.")],
    ]
    monkeypatch.setattr(abstracts, "myresolver", fake_resolver)

    sig = object.__new__(abstracts.Signature)
    ips = sig._get_ip_by_host_dns("example.com")
    assert ips == ["1.2.3.4"]
    assert fake_resolver.resolve.call_count == 2
    assert fake_resolver.query.call_count == 0


def test_cleaners_delete_folder_handles_readonly_with_onexc(tmp_path):
    from lib.cuckoo.common.cleaners_utils import delete_folder

    target = tmp_path / "ro_dir"
    target.mkdir()
    ro_file = target / "locked.txt"
    ro_file.write_text("data", encoding="utf-8")
    os.chmod(ro_file, stat.S_IREAD)

    with warnings.catch_warnings(record=True) as ws:
        warnings.simplefilter("always", DeprecationWarning)
        delete_folder(str(target))

    assert not target.exists()
    assert [w for w in ws if issubclass(w.category, DeprecationWarning)] == []


@pytest.mark.parametrize("tz_value", ["utc", "UTC", "America/New_York", "Invalid/Zone"])
def test_db_common_utcnow_naive_uses_zoneinfo(monkeypatch, tz_value):
    from lib.cuckoo.core.data import db_common

    monkeypatch.setattr(db_common, "tz_name", tz_value)
    with warnings.catch_warnings(record=True) as ws:
        warnings.simplefilter("always", DeprecationWarning)
        dt = db_common._utcnow_naive()

    assert dt.tzinfo is None
    assert [w for w in ws if issubclass(w.category, DeprecationWarning)] == []


def test_dbus_next_no_deprecation_warnings():
    linux_analyzer_dir = str(Path(__file__).resolve().parent.parent / "analyzer" / "linux")
    added = linux_analyzer_dir not in sys.path
    if added:
        sys.path.insert(0, linux_analyzer_dir)
    try:
        for mod_name in list(sys.modules):
            if mod_name == "dbus_next" or mod_name.startswith("dbus_next."):
                del sys.modules[mod_name]

        with warnings.catch_warnings(record=True) as ws:
            warnings.simplefilter("always", DeprecationWarning)
            service_mod = importlib.import_module("dbus_next.service")
            bus_mod = importlib.import_module("dbus_next.aio.message_bus")

            async def _check():
                bus = bus_mod.MessageBus.__new__(bus_mod.MessageBus)
                bus._loop = asyncio.get_running_loop()

                async def _coro(self):
                    return 1

                handler = bus_mod.MessageBus._make_method_handler(bus, None, SimpleNamespace(fn=_coro))
                assert callable(handler)

            asyncio.run(_check())
            assert hasattr(service_mod, "ServiceInterface")

        assert [w for w in ws if issubclass(w.category, DeprecationWarning)] == []
    finally:
        if added and linux_analyzer_dir in sys.path:
            sys.path.remove(linux_analyzer_dir)
