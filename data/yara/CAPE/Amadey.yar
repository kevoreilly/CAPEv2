rule Amadey
{
    meta:
        author = "kevoreilly"
        description = "Amadey Payload"
        cape_type = "Amadey Payload"
    strings:
        $decode = {8B D1 B8 FF FF FF 7F D1 EA 2B C2 3B C8 76 07 BB FF FF FF 7F EB 08 8D 04 0A 3B D8 0F 42 D8}
    condition:
        uint16(0) == 0x5A4D and any of them
}
