rule Ursnif3
{
    meta:
        author = "kevoreilly"
        description = "Ursnif Config Extraction"
        cape_options = "br0=$crypto32-73,dumpsize=eax,action1=dumpebx,dumptype1=0x24,bp2=$timing_trap-6,action2=setesi:9,count=1"
    strings:
        $timing_trap = {6A 02 8B F8 58 8B CE D3 E0 50 FF 15 [4] 83 FF 01 74}
        $crypto32_1 = {8B C3 83 EB 01 85 C0 75 0D 0F B6 16 83 C6 01 89 74 24 14 8D 58 07 8B C2 C1 E8 07 83 E0 01 03 D2 85 C0 0F 84 AB 01 00 00 8B C3 83 EB 01 85 C0 89 5C 24 20 75 13 0F B6 16 83 C6 01 BB 07 00 00 00}
        $crypto32_2 = {8B 45 EC 0F B6 38 FF 45 EC 33 C9 41 8B C7 23 C1 40 40 D1 EF 75 1B 89 4D 08 EB 45}
    condition:
        ($timing_trap) and any of ($crypto32*)
}

rule UrsnifLoader
{
    meta:
        author = "kevoreilly"
        description = "Ursnif Loader"
        cape_options = "bp0=$timing_trap-6,action0=setesi,count=1"
    strings:
        $timing_trap = {C1 E6 05 56 89 [2-3] FF 15 [4] 8B [2-3] 83 F8 0C 74}
        $snippet1    = {81 E3 FF 0F 00 00 F7 DB 1B DB C1 E8 0C F7 DB 03 D8 8B 45 ?? 03 F0 6A 04 68 00 30 00 00 8B C3 C1 E0 0C 50 6A 00}
    condition:
        ($timing_trap) and any of ($snippet*)
}
