rule RedLeaf
{
    meta:
        author = "kev"
        description = "RedLeaf crypto function"
        cape_type = "RedLeaf Payload"
    strings:
        $crypto = {6A 10 B8 ?? ?? ?? 10 E8 ?? ?? 01 00 8B F1 89 75 E4 8B 7D 08 83 CF 07 81 FF FE FF FF 7F 76 05 8B 7D 08 EB 29 8B 4E 14 89 4D EC D1 6D EC 8B C7 33 D2 6A 03 5B F7 F3 8B 55 EC 3B D0 76 10 BF FE FF FF}
    condition:
        $crypto
}

