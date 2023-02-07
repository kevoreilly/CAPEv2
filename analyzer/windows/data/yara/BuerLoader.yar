rule BuerLoader
{
    meta:
        author = "kevoreilly"
        description = "BuerLoader RDTSC Trap Bypass"
        cape_options = "bp0=$trap+43,action0=skip,count=0"
    strings:
        $trap = {0F 31 89 45 ?? 6A 00 8D 45 ?? 8B CB 50 E8 [4] 0F 31}
    condition:
        uint16(0) == 0x5A4D and any of them
}
