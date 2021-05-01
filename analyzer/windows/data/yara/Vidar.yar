rule Vidar
{
    meta:
        author = "kevoreilly"
        description = "Vidar evasion bypass"
        cape_options = "bp0=$trap+52,action0=jmp:52,count=0"
    strings:
        $trap = {C6 45 ?? 03 E8 [4] 53 6A 01 8D 4D ?? E8 [4] 53 6A 01 8D 4D ?? 88 5D ?? E8 [4] 53 FF 35 [4] 8D 4D ?? E8 [4] 83 F8 FF 74}
    condition:
        uint16(0) == 0x5A4D and any of them
}
