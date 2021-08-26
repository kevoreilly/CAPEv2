rule Bazar
{
    meta:
        author = "kevoreilly"
        cape_type = "Bazar Payload"
    strings:
        $decode = {F7 E9 03 D1 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 2B C8 B8 09 04 02 81 83 C1 7F F7 E9 03 D1 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 2B C8}
    condition:
        uint16(0) == 0x5A4D and any of them
}