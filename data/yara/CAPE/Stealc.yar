rule Stealc
{
    meta:
        author = "kevoreilly"
        description = "Stealc Payload"
        cape_type = "Stealc Payload"
        hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
    strings:
        $anti = {53 57 57 57 FF 15 [4] 8B F0 74 03 75 01 B8 E8 [4] 74 03 75 01 B8}
        $decode = {6A 03 33 D2 8B F8 59 F7 F1 8B C7 85 D2 74 04 2B C2 03 C1 6A 06 C1 E0 03 33 D2 59 F7 F1}
    condition:
        uint16(0) == 0x5A4D and all of them
}
