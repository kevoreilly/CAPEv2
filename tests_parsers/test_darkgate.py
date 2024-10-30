from contextlib import suppress

from modules.processing.parsers.CAPE.DarkGate import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.DarkGate import convert_to_MACO

    HAVE_MACO = True


def test_darkgate():
    with open("tests/data/malware/1c3ae64795b61034080be00601b947819fe071efd69d7fc791a99ec666c2043d", "rb") as data:
        conf = extract_config(data.read())
        assert conf["C2"] == ["http://80.66.88.145"]
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "DarkGate",
                "other": {"C2": ["http://80.66.88.145"]},
                "http": [{"uri": "http://80.66.88.145", "usage": "c2"}],
            }
