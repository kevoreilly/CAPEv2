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
    assert len(matches[0].strings[0]) == 3

    _ = yara.compile(source='import "dotnet" rule a { condition: false }')


def test_get_yaras():
    yara_matches = File("tests/data/malware/53622590bb3138dcbf12b0105af96dd72aedc40de8984f97c8e882343a769b45").get_yara(category="CAPE")
    assert yara_matches == [{'name': 'RedLine', 'meta': {'author': 'ditekSHen', 'description': 'Detects RedLine infostealer', 'cape_type': 'RedLine Payload'}, 'strings': ['procName'], 'addresses': {'v4_8': 100177}}]
    yara_matches = File("tests/data/malware/f8a6eddcec59934c42ea254cdd942fb62917b5898f71f0feeae6826ba4f3470d").get_yara(category="CAPE")
    assert yara_matches == [{'name': 'BumbleBee', 'meta': {'author': 'enzo & kevoreilly', 'description': 'BumbleBee Payload', 'cape_type': 'BumbleBee Payload'}, 'strings': ['/gate'], 'addresses': {'str_gate': 1911968}}]


"""
def test_yara_moduels():
    if not HAVE_YARA:
        return
    assert sorted(yara.modules) == ["console", "cuckoo", "dotnet", "elf", "hash", "magic", "math", "pe", "string", "tests", "time"]
"""
