rule Ursnif3
{
    meta:
        author = "kevoreilly"
        description = "Ursnif Payload"
        cape_type = "Ursnif Payload"
    strings:
        $crypto32_1 = {8B C3 83 EB 01 85 C0 75 0D 0F B6 16 83 C6 01 89 74 24 14 8D 58 07 8B C2 C1 E8 07 83 E0 01 03 D2 85 C0 0F 84 AB 01 00 00 8B C3 83 EB 01 85 C0 89 5C 24 20 75 13 0F B6 16 83 C6 01 BB 07 00 00 00}
        $crypto32_2 = {8B 45 EC 0F B6 38 FF 45 EC 33 C9 41 8B C7 23 C1 40 40 D1 EF 75 1B 89 4D 08 EB 45}
        $cape_string = "cape_options"
    condition:
        uint16(0) == 0x5A4D and 1 of ($crypto32_*) and not $cape_string
}
