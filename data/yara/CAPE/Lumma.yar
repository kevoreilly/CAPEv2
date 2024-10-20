rule Lumma
{
    meta:
        author = "kevoreilly,YungBinary"
        description = "Lumma Payload"
        cape_type = "Lumma Payload"
        packed = "5d58bc449693815f6fb0755a364c4cd3a8e2a81188e431d4801f2fb0b1c2de8f"
    strings:
        $xor_decode = {
            0F B6 14 0E
            89 CF
            83 E7 1F
            0F B6 7C 3C ??
            89 D3
            31 FB
            83 F3 FF
            89 FD
            21 DD
            D1 E5
            29 FD
            29 EA
            8B 5C 24 ??
            88 14 0B
            EB ??
        }
        $c2 = {8D 44 24 ?? 50 89 4C 24 ?? FF 31 E8 [4] 83 C4 08 B8 FF FF FF FF}
        $peb = {8B 44 24 04 85 C0 74 13 64 8B 0D 30 00 00 00 50 6A 00 FF 71 18 FF 15}
        $remap = {C6 44 24 20 00 C7 44 24 1C C2 00 00 90 C7 44 24 18 00 00 FF D2 C7 44 24 14 00 BA 00 00 C7 44 24 10 B8 00 00 00 8B ?? 89 44 24 11}

    condition:
        uint16(0) == 0x5a4d and any of them
}
