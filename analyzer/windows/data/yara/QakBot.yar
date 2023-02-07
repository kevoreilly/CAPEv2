rule QakBot
{
    meta:
        author = "kevoreilly"
        description = "QakBot AntiVM bypass"
        cape_options = "bp0=$antivm1,action0=unwind,count=1"
        hash = "e269497ce458b21c8427b3f6f6594a25d583490930af2d3395cb013b20d08ff7"
    strings:
        $antivm1 = {55 8B EC 3A E4 0F [2] 00 00 00 6A 04 58 3A E4 0F [2] 00 00 00 C7 44 01 [5] 81 44 01 [5] 66 3B FF 74 ?? 6A 04 58 66 3B ED 0F [2] 00 00 00 C7 44 01 [5] 81 6C 01 [5] EB}
    condition:
        any of them
}

rule QakBotLoader
{
    meta:
        author = "kevoreilly"
        description = "QakBot Export Selection"
        cape_options = "export=$export1-307,export=$export2-105"
    strings:
        $export1 = {66 3B E4 74 34 F7 F6 0F B6 44 15 ?? 33 C8 EB ?? BB D2 04 00 00 53 E8 [4] 66 3B FF 74 ?? 0F B6 4C 05 ?? 8B 45 ?? 33 D2 3A D2 74}
        $export2 = {66 3B F6 74 0B FF 75 ?? BB 00 00 00 00 53 EB ?? BB D2 04 00 00 53 E8 [4] 3A FF 74 ?? 0F B6 4C 05 ?? 8B 45 ?? 33 D2 66 3B D2 74}
    condition:
        uint16(0) == 0x5A4D and any of them
}
