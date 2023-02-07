rule Scarab
{
    meta:
        author = "kevoreilly"
        description = "Scarab Payload"
        cape_type = "Scarab Payload"
    strings:
        $crypt1 = {8B D8 32 1A 0F B6 DB 8B 1C 9F C1 E8 08 33 D8 8B C3 42 8B D8 32 1A 0F B6 DB 8B 1C 9F C1 E8 08 33 D8 8B C3 42 8B D8 32 1A 0F B6 DB 8B 1C 9F C1 E8 08}
        $crypt2 = {8B 4C 82 0C 8B D9 C1 E3 18 C1 E9 08 0B D9 8B CB 0F B6 D9 8B 1C 9D AC 0C 43 00 89 5C 24 04 8B D9 C1 EB 08 0F B6 DB 8B 34 9D AC 0C 43 00 8B D9 C1 EB 10}
        $crypt3 = {8B 13 8B CA 81 E1 80 80 80 80 8B C1 C1 E8 07 50 8B C1 59 2B C1 25 1B 1B 1B 1B 8B CA 81 E1 7F 7F 7F 7F 03 C9 33 C1 8B C8 81 E1 80 80 80 80 8B F1 C1 EE 07}
    condition:
        uint16(0) == 0x5A4D and all of them
}
