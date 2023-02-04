rule UrsnifV3
{
    meta:
        author = "kevoreilly"
        description = "Ursnif Config Extraction"
        cape_options = "br0=$crypto32-73,dumpsize=eax,action1=dump:ebx,typestring1=UrsnifV3 Config,bp2=$timing_trap-6,action2=setesi:9,count=1"
    strings:
        $timing_trap = {6A 02 8B F8 58 8B CE D3 E0 50 FF 15 [4] 83 FF 01 74}
        $crypto32_1 = {8B C3 83 EB 01 85 C0 75 0D 0F B6 16 83 C6 01 89 74 24 14 8D 58 07 8B C2 C1 E8 07 83 E0 01 03 D2 85 C0 0F 84 AB 01 00 00 8B C3 83 EB 01 85 C0 89 5C 24 20 75 13 0F B6 16 83 C6 01 BB 07 00 00 00}
        $crypto32_2 = {8B 45 EC 0F B6 38 FF 45 EC 33 C9 41 8B C7 23 C1 40 40 D1 EF 75 1B 89 4D 08 EB 45}
    condition:
        ($timing_trap) or any of ($crypto32*)
}
