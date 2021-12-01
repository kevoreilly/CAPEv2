rule Emotet
{
    meta:
        author = "kevoreilly"
        description = "Emotet bypass"
        cape_options = "bp0=$trap+31,action0=skip,count=1"
    strings:
        $trap = {8B 45 08 0F 28 0D [4] 0F 57 C0 0F 29 46 30 89 46 40 C7 46 44 00 00 00 00 0F 11 4E 48 E8}
    condition:
        uint16(0) == 0x5A4D and $trap
}
 