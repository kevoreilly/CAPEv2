rule DridexLoader
{
    meta:
        author = "kevoreilly"
        description = "DridexLoader API Spam Bypass"
        cape_options = "bp0=$trap-13,action0=ret,count=0"
    strings:
        $trap = {6A 50 6A 14 6A 03 5A 8D 4C 24 ?? E8 [4] 68 [4] 68 [4] E8 [4] 85 C0 74 05}
    condition:
        uint16(0) == 0x5A4D and $trap
}
