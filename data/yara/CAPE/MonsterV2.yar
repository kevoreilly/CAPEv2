rule MonsterV2
{
    meta:
        author = "doomedraven,YungBinary"
        description = "MonsterV2 Payload"
        cape_type = "MonsterV2 Payload"
        packed = "fe69e8db634319815270aa0e55fe4b9c62ce8e62484609c3a42904fbe5bb2ab3"
    strings:
        $decrypt_config = {
            41 B8 0E 04 00 00
            48 8D 15 ?? ?? ?? 00
            48 8B C?
            E8 ?? ?? ?? ?? [3-17]
            4C 8B C?
            48 8D 54 24 28
            48 8B CE
            E8 ?? ?? ?? ??
        }
    condition:
        uint16(0) == 0x5A4D and $decrypt_config
}
