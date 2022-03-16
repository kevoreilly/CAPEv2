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
