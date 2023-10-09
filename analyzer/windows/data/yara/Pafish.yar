rule Pafish
{
    meta:
        author = "kevoreilly"
        description = "Pafish bypass"
        cape_options = "bp0=$rdtsc_vmexit_32-2,bp1=$rdtsc_vmexit_32-2,bp0=$rdtsc_vmexit_64+36,bp1=$rdtsc_vmexit_64+36,action0=skip,action1=skip,count=1"
        hash = "9e7d694ed87ae95f9c25af5f3a5cea76188cd7c1c91ce49c92e25585f232d98e"
        hash = "ff24b9da6cddd77f8c19169134eb054130567825eee1008b5a32244e1028e76f"
    strings:
        $rdtsc_vmexit_32 = {8B 45 E8 80 F4 00 89 C? 8B 45 EC 80 F4 00 89 C? 89 F? 09 ?? 85 C0 75 07}
        $rdtsc_vmexit_64 = {48 8B 45 F0 48 BA CD CC CC CC CC CC CC CC 48 F7 E2 48 89 D0 48 C1 E8 03 48 89 45 F0 48 81 7D F0 ?? 0? 00 00 77 07}
    condition:
        uint16(0) == 0x5A4D and any of them
}
