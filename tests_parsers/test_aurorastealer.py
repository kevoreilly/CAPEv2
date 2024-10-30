from contextlib import suppress

from modules.processing.parsers.CAPE.AuroraStealer import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.AuroraStealer import convert_to_MACO

    HAVE_MACO = True


def test_aurorastealer():
    with open("tests/data/malware/8da8821d410b94a2811ce7ae80e901d7e150ad3420d677b158e45324a6606ac4", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "BuildID": "x64pump",
            "MD5Hash": "f29f33b296b35ec5e7fc3ee784ef68ee",
            "C2": "77.91.85.73",
            "Architecture": "X64",
            "BuildGroup": "x64pump",
            "BuildAccept": "0",
            "Date": "2023-04-06 19",
        }

        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "AuroraStealer",
                "other": {
                    "BuildID": "x64pump",
                    "MD5Hash": "f29f33b296b35ec5e7fc3ee784ef68ee",
                    "C2": "77.91.85.73",
                    "Architecture": "X64",
                    "BuildGroup": "x64pump",
                    "BuildAccept": "0",
                    "Date": "2023-04-06 19",
                },
                "http": [{"hostname": "77.91.85.73", "usage": "c2"}],
            }
