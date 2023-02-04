rule Netwalker
{
    meta:
        author = "kevoreilly"
        description = "Netwalker Ransomware Payload"
        cape_type = "Netwalker Payload"
    strings:
        $decode = {FF 74 24 ?? 8A CB 50 8B C6 C0 E1 02 E8 [4] D3 C0 83 F3 01 89 02 83 C2 04 FF 4C 24 ?? 8B C6 75 CB 5E 5B C2 08 00}
        $zero2auto = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b 98 2f 8a 42}
    condition:
        uint16(0) == 0x5A4D and any of them
}
