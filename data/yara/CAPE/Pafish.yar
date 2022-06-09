rule Pafish
{
    meta:
        author = "kevoreilly"
        description = "Paranoid Fish Sandbox Detection"
        cape_type = "Pafish Payload"
    strings:
        $rdtsc_vmexit = {8B 45 E8 80 F4 00 89 C3 8B 45 EC 80 F4 00 89 C6 89 F0 09 D8 85 C0 75 07}
        $cape_string = "cape_options"
    condition:
        uint16(0) == 0x5A4D and $rdtsc_vmexit and not $cape_string
}
