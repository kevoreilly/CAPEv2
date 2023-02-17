rule QakBot
{
    meta:
        author = "kevoreilly"
        description = "QakBot Config Extraction"
        cape_options = "bp0=$params+23,action0=setdump:eax::ecx,bp1=$c2list1+40,bp1=$c2list2+38,action1=dump,bp2=$conf+13,action2=dump,count=1,typestring=QakBot Config"
        packed = "f084d87078a1e4b0ee208539c53e4853a52b5698e98f0578d7c12948e3831a68"
    strings:
        $params = {8B 7D ?? 8B F1 57 89 55 ?? E8 [4] 8D 9E [2] 00 00 89 03 59 85 C0 75 08 6A FC 58 E9}
        $c2list1 = {59 59 8D 4D D8 89 45 E0 E8 [4] 8B 45 E0 85 C0 74 ?? 8B 90 [2] 00 00 51 8B 88 [2] 00 00 6A 00 E8}
        $c2list2 = {59 59 8B F8 8D 4D ?? 89 7D ?? E8 [4] 85 FF 74 52 8B 97 [2] 00 00 51 8B 8F [2] 00 00 53 E8}
        $conf = {5F 5E 5B C9 C3 51 6A 00 E8 [4] 59 59 85 C0 75 01 C3}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule QakBotLoader
{
    meta:
        author = "kevoreilly"
        description = "QakBot Export Selection"
        cape_options = "export=$export"
        hash = "6f99171c95a8ed5d056eeb9234dbbee123a6f95f481ad0e0a966abd2844f0e1a"
    strings:
        $export = {55 8B EC 83 EC 50 (3A|66 3B) ?? 74}
        $wind = {(66 3B|3A) ?? 74 [1-14] BB 69 04 00 00 53 E8 [5-7] 74}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule QakBotAntiVM
{
    meta:
        author = "kevoreilly"
        description = "QakBot AntiVM bypass"
        cape_options = "bp0=$antivm1,action0=unwind,count=1"
        hash = "e269497ce458b21c8427b3f6f6594a25d583490930af2d3395cb013b20d08ff7"
    strings:
        $antivm1 = {55 8B EC 3A E4 0F [2] 00 00 00 6A 04 58 3A E4 0F [2] 00 00 00 C7 44 01 [5] 81 44 01 [5] 66 3B FF 74 ?? 6A 04 58 66 3B ED 0F [2] 00 00 00 C7 44 01 [5] 81 6C 01 [5] EB}
    condition:
        all of them
}
