rule Zloader
{
    meta:
        author = "kevoreilly"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
    strings:
        $decode1 = {89 ?8 [0-6] 99 F7 7D ?? 8B 45 ?? 0F B? ?C 1? [0-3] (32|66 33) [2] (66|88) [2-3] 8D [2] 74}
        $decode2 = {55 89 E5 56 50 A0 [4] 00 C0 0C 20 0F BE C8 F6 D8 0F BE D0 BE [4] 33 35 [4] 39 CE 89 D0 7C 13 39 D6 89 D0 75 36 85 F6 74 3B}
    condition:
        uint16(0) == 0x5A4D and any of them
}
