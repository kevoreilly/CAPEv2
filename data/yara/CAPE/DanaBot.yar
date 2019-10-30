rule DanaBot
{
    meta:
        author = "kevoreilly"
        description = "DanaBot decrypt function"
        cape_type = "DanaBot Payload"

    strings:
        $decrypt1 = {83 FA 20 88 CD 7C 3F 66 89 08 66 89 48 02 66 89 48 04 66 89 48 06 83 EA 10 DD 00 DD 14 02 DD 54 02 08 89 C1 83 E1 07 83 E9 08 29 C8 01 CA 01 D0 F7 DA DD 14 02 DD 54 02 08 83 C2 10 7C F4 DD C0 D9 F7 C3}
    
    condition:
        uint16(0) == 0x5A4D and any of them
}
