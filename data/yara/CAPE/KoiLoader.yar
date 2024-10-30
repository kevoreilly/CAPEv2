rule KoiLoader
{
    meta:
        author = "YungBinary"
        description = "KoiLoader"
        cape_type = "KoiLoader Payload"
        hash = "b462e3235c7578450b2b56a8aff875a3d99d22f6970a01db3ba98f7ecb6b01a0"
    strings:
        $chunk_1 = {
            68 27 11 68 05
            8B 45 ??
            50
            E8 ?? ?? ?? ??
            83 C4 08
            89 45 ??
            68 15 B1 B3 09
            8B 4D ??
            51
            E8 ?? ?? ?? ??
            83 C4 08
            89 45 ??
            68 B5 96 AA 0D
            8B 55 ??
            52
            E8 ?? ?? ?? ??
            83 C4 08
            89 45 ??
            6A 00
            FF 15 ?? ?? ?? ??
        }

    condition:
        $chunk_1

}
