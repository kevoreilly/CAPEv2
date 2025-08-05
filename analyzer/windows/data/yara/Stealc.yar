rule StealcAnti
{
    meta:
        author = "kevoreilly"
        description = "Stealc detonation bypass"
        cape_options = "bp0=$anti+17,action0=skip,count=1"
        hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
    strings:
        $anti = {53 57 57 57 FF 15 [4] 8B F0 74 03 75 01 B8 E8 [4] 74 03 75 01 B8}
        $decode = {6A 03 33 D2 8B F8 59 F7 F1 8B C7 85 D2 74 04 2B C2 03 C1 6A 06 C1 E0 03 33 D2 59 F7 F1}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule StealcStrings
{
    meta:
        author = "kevoreilly"
        description = "Stealc string decryption"
        cape_options = "bp0=$decode+17,action0=string:edx,count=0,typestring=Stealc Strings"
        packed = "d0c824e886f14b8c411940a07dc133012b9eed74901b156233ac4cac23378add"
    strings:
        $decode = {51 8B 15 [4] 52 8B 45 ?? 50 E8 [4] 83 C4 0C 6A 04 6A 00 8D 4D ?? 51 FF 15 [4] 83 C4 0C 8B 45 ?? 8B E5 5D C3}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule StealcV2Strings
{
    meta:
        author = "kevoreilly"
        description = "StealcV2 string decryption"
        cape_options = "bp0=$decode32*,action0=string:[esp],bp1=$decode64,action1=string:eax,bp2=$dump,action2=dumpstrings,count=0,typestring=Stealc Strings"
        packed = "2f42dcf05dd87e6352491ff9d4ea3dc3f854df53d548a8da0c323be42df797b6"
        packed = "8301936f439f43579cffe98e11e3224051e2fb890ffe9df680bbbd8db0729387"
    strings:
        $decode32 = {AB AB AB AB 8B 45 0C 89 4E 10 89 4E 14 39 45 08 75 0B C7 46 14 0F 00 00 00 88 0E EB 0F 2B 45 08 50 51 FF 75 ?? 8B}
        $decode64 = {40 53 48 83 EC 20 48 8B 19 48 85 DB 74 ?? 48 8B 53 18 48 83 FA 0F 76 2C 48 8B 0B 48 FF C2 48 81 FA 00 10 00 00 72}
        $dump32 = {33 C0 89 46 30 88 46 34 89 46 38 89 46 3C 89 46 40 89 46 44 89 46 48 89 46 4C 89 46 50 89 46 54 89 46 58 8B C6 5F 5E C3}
        $dump64 = {48 8B C7 89 6F 40 40 88 6F 44 48 89 6F 48 48 89 6F 50 48 89 6F 58 48 89 6F 60 48 89 6F 68 48 89 6F 70 48 89 6F 78 48 89}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule StealcV2DateCheck
{
    meta:
        author = "kevoreilly"
        description = "StealcV2 date check bypass"
        cape_options = "patch=$date32*-1:B000,patch=$date64*-2:B00090"
    strings:
        $date32 = {F3 A5 8D 45 ?? 50 E8 [4] 59 8B F8 8B F2 8D 45 A4 50 E8 [4] 59 3B F2 7C 08 7F 04 3B F8 76 02 B3 01 8A C3}
        $date64 = {0F 11 44 [2] 0F 11 8C [2] 00 00 00 89 8C [2] 00 00 00 48 8D 4C [2] E8 [4] 48 8B D8 48 8D 4C [2] E8 [4] 48 3B D8 0F 9F C0}
    condition:
        uint16(0) == 0x5A4D and any of them
}
