rule MatanbuchusLoader
{
    meta:
        description = "Detects Matanbuchus loader (BelialDropper) used to download Matanbuchus payload"
        author = "Rony (@r0ny_123)"
        cape_type = "Matanbuchus loader"
        cretaion_date = "2021-12-09"
        revision = "0"
        reference = "https://www.capesandbox.com/analysis/212747"
    strings:
        /*
        8B 55 FC          mov     edx, [ebp+var_4]
        8B CA             mov     ecx, edx
        C1 E1 04          shl     ecx, 4
        03 C1             add     eax, ecx
        8B 4D F8          mov     ecx, [ebp+var_8]
        33 F0             xor     esi, eax
        8B 45 10          mov     eax, [ebp+arg_8]
        03 C1             add     eax, ecx
        33 F0             xor     esi, eax
        03 75 F0          add     esi, [ebp+var_10]
        */
        $ = { 8B 55 ?? 8B CA C1 E1 ?? 03 C1 8B 4D ?? 33 F0 8B 45 ?? 03 C1 33 F0 03 75 }
    condition:
        uint16be(0) == 0x4d5a and uint32be(uint32(0x3c)) == 0x50450000 and all of them
}
