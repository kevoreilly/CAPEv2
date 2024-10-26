from modules.processing.parsers.CAPE.AsyncRAT import extract_config
from modules.processing.parsers.MACO.AsyncRAT import convert_to_MACO


def test_asyncrat():
    with open("tests/data/malware/f08b325f5322a698e14f97db29d322e9ee91ad636ac688af352d51057fc56526", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "C2s": ["todfg.duckdns.org"],
            "Ports": "6745",
            "Version": "0.5.7B",
            "Folder": "%AppData%",
            "Filename": "updateee.exe",
            "Install": "false",
            "Mutex": "AsyncMutex_6SI8OkPnk",
            "Pastebin": "null",
        }

        assert convert_to_MACO(conf).model_dump == {
            "family": "AsyncRAT",
            "version": "0.5.7B",
            "capability_disabled": ["persistence"],
            "mutex": ["AsyncMutex_6SI8OkPnk"],
            "http": [{"hostname": "todfg.duckdns.org", "port": 6, "usage": "c2"}],
            "paths": [{"path": "%AppData%/updateee.exe", "usage": "install"}],
        }
