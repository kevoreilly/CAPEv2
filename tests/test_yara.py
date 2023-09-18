# import pytest

from lib.cuckoo.common.objects import File

try:
    import yara

    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False


def test_yara():
    if not HAVE_YARA:
        return

    rules = yara.compile(
        source="""
        rule Test {
            strings:
                $ = "aaaaa"
                $ = "bbbbb"
                $ = "ccccc"
            condition:
                any of them
        }
    """
    )
    # print("Yara version %s" % yara.__version__)
    matches = rules.match(data="asdfklahjsdflkhjsd aaaaa dfgkhjadsfgjklsdfhgk")
    assert isinstance(matches[0].strings[0], yara.StringMatch)

    _ = yara.compile(source='import "dotnet" rule a { condition: false }')


def test_get_yaras():
    File.init_yara()
    yara_matches = File("tests/data/malware/f8a6eddcec59934c42ea254cdd942fb62917b5898f71f0feeae6826ba4f3470d").get_yara(
        category="CAPE"
    )
    assert yara_matches == [
        {
            "name": "BumbleBee",
            "meta": {"author": "enzo & kevoreilly", "description": "BumbleBee Payload", "cape_type": "BumbleBee Payload"},
            "strings": ["{ 84 C0 74 09 33 C9 FF 15 34 AF 15 00 CC 33 C9 E8 34 8E 12 00 48 8B C8 E8 }", "/gate"],
            "addresses": {"antivm1": 34936, "str_gate": 1911968},
        }
    ]


"""
def test_yara_moduels():
    if not HAVE_YARA:
        return
    assert sorted(yara.modules) == ["console", "cuckoo", "dotnet", "elf", "hash", "magic", "math", "pe", "string", "tests", "time"]
"""
