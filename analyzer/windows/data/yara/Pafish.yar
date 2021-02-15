rule Pafish
{
    meta:
        author = "kevoreilly"
        description = "Pafish bypass"
        cape_options = "bp0=$rdtsc_vmexit-2,action0=skip,bp1=$rdtsc_vmexit-2,action1=skip,count=1"
    strings:
        $rdtsc_vmexit = {8B 45 E8 80 F4 00 89 C3 8B 45 EC 80 F4 00 89 C6 89 F0 09 D8 85 C0 75 07}
    condition:
        uint16(0) == 0x5A4D and $rdtsc_vmexit
}
 