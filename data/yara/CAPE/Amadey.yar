rule Amadey
{
    meta:
        author = "kevoreilly"
        description = "Amadey Payload"
        cape_type = "Amadey Payload"
        hash = "988258716d5296c1323303e8fe4efd7f4642c87bfdbe970fe9a3bb3f410f70a4"
    strings:
        $decode1 = {8B D1 B8 FF FF FF 7F D1 EA 2B C2 3B C8 76 07 BB FF FF FF 7F EB 08 8D 04 0A 3B D8 0F 42 D8}
        $decode2 = {33 D2 8B 4D ?? 8B C7 F7 F6 8A 84 3B [4] 2A 44 0A 01 88 87 [4] 47 8B 45 ?? 8D 50 01}
        $decode3 = {8A 04 02 88 04 0F 41 8B 7D ?? 8D 42 01 3B CB 7C}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
