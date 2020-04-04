rule Netwalker
{
    meta:
        author = "kevoreilly"
        description = "Netwalker Ransomware Payload"
        cape_type = "Netwalker Payload"
    strings:
        $decode = {FF 74 24 ?? 8A CB 50 8B C6 C0 E1 02 E8 [4] D3 C0 83 F3 01 89 02 83 C2 04 FF 4C 24 ?? 8B C6 75 CB 5E 5B C2 08 00}
    condition:
        uint16(0) == 0x5A4D and all of them
}
