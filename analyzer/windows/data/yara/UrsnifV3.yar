rule UrsnifV3
{
    meta:
        author = "kevoreilly"
        description = "Ursnif Config Extraction"
        cape_options = "br0=$crypto32_1-48,br0=$crypto32_2-80,action1=dump:ebx::eax,bp2=$crypto32_3+50,action2=dump:ebx::eax,typestring=UrsnifV3 Config,count=1"
    strings:
        $crypto32_1 = {8B C3 83 EB 01 85 C0 75 0D 0F B6 16 83 C6 01 89 74 24 14 8D 58 07 8B C2 C1 E8 07 83 E0 01 03 D2 85 C0 0F 84 AB 01 00 00 8B C3 83 EB 01 85 C0 89 5C 24 20 75 13 0F B6 16 83 C6 01 BB 07 00 00 00}
        $crypto32_3 = {F6 46 03 02 75 59 8B 46 10 40 50 E8 [4] 8B D8 89 5C 24 1C 85 DB 74 41 F6 46 03 01 74 53 8B 46 10 89 44 24 1C 8B 46 0C 53 03 C7 E8 [4] 59}
        $cpuid = {8B C4 FF 18 8B F0 33 C0 0F A2 66 8C D8 66 8E D0 8B E5 8B C6 5E 5B 5D C3}
    condition:
        any of ($crypto32*) and $cpuid
}
