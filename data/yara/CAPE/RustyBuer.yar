rule RustyBuer
{
    meta:
        author = "Rony (@r0ny_123)"
        description = "Detects unpacked buer written in rust"
        cape_type = "RustyBuer Payload"
    strings:
        $code = { f6 c2 ?? 75 ?? 8d 1c 01 6a ?? 50 51 6a ?? e8 [4] 89 c7 31 c0 b2 ?? 89 d9 81 ff [4] 72 ?? 81 f7 }
        $s = "NtQueryDefaultLocale"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
