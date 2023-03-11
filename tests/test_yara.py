import yara

def test_yara():
    rules = yara.compile(source="""
        rule Test {
            strings:
                $ = "aaaaa"
                $ = "bbbbb"
                $ = "ccccc"
            condition:
                any of them
        }
    """)
    # print("Yara version %s" % yara.__version__)
    matches = rules.match(data="asdfklahjsdflkhjsd aaaaa dfgkhjadsfgjklsdfhgk")
    assert len(matches[0].strings) == 3
    # assert sorted(yara.modules) == ['console', 'cuckoo', 'dotnet', 'elf', 'hash', 'magic', 'math', 'pe', 'string', 'tests', 'time']
