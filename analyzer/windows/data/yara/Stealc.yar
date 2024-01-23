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
        cape_options = "bp0=$decode+17,action0=string:edx,count=1,typestring=Stealc Strings"
        packed = "d0c824e886f14b8c411940a07dc133012b9eed74901b156233ac4cac23378add"
    strings:
        $decode = {51 8B 15 [4] 52 8B 45 ?? 50 E8 [4] 83 C4 0C 6A 04 6A 00 8D 4D ?? 51 FF 15 [4] 83 C4 0C 8B 45 ?? 8B E5 5D C3}
    condition:
        uint16(0) == 0x5A4D and any of them
}
