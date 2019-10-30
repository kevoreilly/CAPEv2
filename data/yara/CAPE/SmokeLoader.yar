rule SmokeLoader
{
    meta:
        author = "kev"
        description = "SmokeLoader C2 decryption function"
        cape_type = "SmokeLoader Payload"
    strings:
        $decrypt64_1 = {44 0F B6 CF 48 8B D0 49 03 D9 4C 2B D8 8B 4B 01 41 8A 04 13 41 BA 04 00 00 00 0F C9 32 C1 C1 F9 08 49 FF CA 75 F6 F6 D0 88 02 48 FF C2 49 FF C9 75 DB 49 8B C0 48 8B 5C 24 30 48 83 C4 20 5F C3}
        $decrypt64_2 = {40 84 FF 90 90 E8 00 00 00 00 5E 48 83 C6 1C 49 8B F8 A4 80 3E 00 75 FA 80 07 00 48 8B 5C 24 30 48 83 C4 20 5F C3}
        $decrypt32_1 = {03 EE 8B D7 2B C7 8B F8 8B 4D 01 8A 04 17 6A 04 0F C9 5B 32 C1 C1 F9 08 4B 75 F8 F6 D0 88 02 42 4E 75 E5 8B 7C 24 14 8B C7 5F 5E 5D 5B 59 59 C3}
    condition:
        any of ($decrypt*)
}