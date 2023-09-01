import "pe"
rule Amadey
{
    meta:
        author = "kevoreilly"
        description = "Amadey Payload"
        cape_type = "Amadey Payload"
    strings:
        $decode1 = {8B D1 B8 FF FF FF 7F D1 EA 2B C2 3B C8 76 07 BB FF FF FF 7F EB 08 8D 04 0A 3B D8 0F 42 D8}
        $decode2 = {33 D2 8B 4D ?? 8B C7 F7 F6 8A 84 3B [4] 2A 44 0A 01 88 87 [4] 47 8B 45 ?? 8D 50 01}
        $decode3 = {42 8B C1 81 FA 00 10 00 00 72 14 8B 49 FC 83 C2 23 2B C1 83 C0 FC 83 F8 1F}
        $decode4 = {8A 04 02 88 04 0F 41 8B 7D ?? 8D 42 01 3B CB 7C ?? 83 7E ?? 10 72}
    condition:
        pe.is_pe and 2 of them
}
