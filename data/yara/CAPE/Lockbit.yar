rule Lockbit
{
    meta:
        author = "kevoreilly"
        description = "Lockbit Payload"
        cape_type = "Lockbit Payload"
    strings:
        $crypto = {8B 4D 08 C1 E9 10 0F B6 D1 8B 4D 0C C1 E9 08 0F B6 C9 8B 14 95 [4] 8B 7D FC 33 14 8D [4] 8B CF C1 E9 18 33 14 8D [4] 0F B6 CB 33 14 8D [4] 8B CF 33 10}
    condition:
        uint16(0) == 0x5A4D and (any of them)
} 