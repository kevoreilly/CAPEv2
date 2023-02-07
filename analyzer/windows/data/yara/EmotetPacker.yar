rule EmotetPacker
{
    meta:
        author = "kevoreilly"
        description = "Emotet bypass"
        cape_options = "bp0=$trap1+31,action0=skip,bp1=$trap2+43,action1=jmp:186,count=1"
        hash = "5a95d1d87ce69881b58a0e3aafc1929861e2633cdd960021d7b23e2a36409e0d"
    strings:
        $trap1 = {8B 45 08 0F 28 0D [4] 0F 57 C0 0F 29 46 30 89 46 40 C7 46 44 00 00 00 00 0F 11 4E 48 E8}
        $trap2 = {F2 0F 10 15 [4] BE 01 00 00 00 0F 01 F9 C7 44 24 60 00 00 00 00 89 4C 24 60 0F 01 F9 C7 44 24 5C 00 00 00 00 89 4C 24 5C 0F 1F 84 00 00 00 00 00}
    condition:
        uint16(0) == 0x5A4D and any of ($trap*)
}
