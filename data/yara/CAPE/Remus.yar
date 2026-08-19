rule Remus
{
    meta:
        author = "kevoreilly"
        cape_type = "Remus Payload"
        packed = "f67a176503343855c88d9aac1217277ee4e2badc5e56fe403e56ca30e144b266"
    strings:
        $wmi = {48 89 F9 45 31 C0 FF D0 48 83 C4 30 85 C0 0F 99 C0 66 8B [1-4] 00 66 83 E9 08 0F 94 C1 20 C8}
        $dec1 = {0F B6 04 0B 41 88 04 (0A|0B) 0F B6 44 0B 01 41 88 44 (0A|0B) 01 0F B6 44 0B 02 41 88 44 (0A|0B) 02 0F B6 44 0B 03 41 88 44 (0A|0B) 03 48 83 C1 04 49 39 C9 75 D1 90}
        $dec2 = {48 B9 00 00 00 00 00 00 F8 7F 48 39 C8 0F 9F C1 48 BA 00 00 00 00 00 80 07 00 48 21 C2 48 B8 00 00 00 00 00 00 02 00 48 39 C2 0F 94 C0 20 C8 0F B6 C0 48 8D 0D [4] FF 24 C1}
        $c2 = {C1 E0 06 48 8D 15 [4] 48 01 C2 48 8D 0D [4] 48 8D B4 24 [2] 00 00 49 89 F0 E8 [4] 48 8D 0D [4] BA 40 00 00 00 49 89 F0 45 31 C9 E8 [4] 40 B6 01 E9}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
