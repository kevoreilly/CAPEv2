# import pytest

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


"""
def test_yara_moduels():
    if not HAVE_YARA:
        return
    assert sorted(yara.modules) == ["console", "cuckoo", "dotnet", "elf", "hash", "magic", "math", "pe", "string", "tests", "time"]
"""
