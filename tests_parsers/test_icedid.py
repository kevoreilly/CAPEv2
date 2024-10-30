from contextlib import suppress

from modules.processing.parsers.CAPE.IcedIDLoader import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.IcedIDLoader import convert_to_MACO

    HAVE_MACO = True


def test_icedid():
    with open("tests/data/malware/7aaf80eb1436b946b2bd710ab57d2dcbaad2b1553d45602f2f3af6f2cfca5212", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"C2": "anscowerbrut.com", "Campaign": 2738000827}
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "IcedIDLoader",
                "campaign_id": ["2738000827"],
                "other": {"C2": "anscowerbrut.com", "Campaign": 2738000827},
                "http": [{"hostname": "anscowerbrut.com", "usage": "c2"}],
            }
