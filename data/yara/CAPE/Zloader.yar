rule Zloader
{
    meta:
        author = "kevoreilly"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
    strings:
        $rc4_init = {31 [1-3] 66 C7 8? 00 01 00 00 00 00 90 90 [0-5] 8? [5-90] 00 01 00 00 [0-15] (74|75)}
        $decrypt_conf = {83 C4 04 84 C0 74 5? E8 [4] E8 [4] E8 [4] E8 [4] ?8 [4] ?8 [4] ?8}
    condition:
        uint16(0) == 0x5A4D and any of them
}
