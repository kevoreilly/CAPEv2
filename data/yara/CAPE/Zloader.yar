rule Zloader
{
    meta:
        author = "kevoreilly"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
    strings:
        $decode = {89 ?8 [0-6] 99 F7 7D ?? 8B 45 ?? 0F B? ?C 1? [0-3] (32|66 33) [2] (66|88) [2-3] 8D [2] 74}
    condition:
        uint16(0) == 0x5A4D and all of them
}
