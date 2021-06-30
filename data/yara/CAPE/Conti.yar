rule Conti
{
    meta:
        author = "kevoreilly"
        description = "Conti Ransomware"
        cape_type = "Conti Payload"
    strings:
        $crypto1 = {8A 07 8D 7F 01 0F B6 C0 B9 ?? 00 00 00 2B C8 6B C1 ?? 99 F7 FE 8D [2] 99 F7 FE 88 ?? FF 83 EB 01 75 DD}
        $website1 = "https://contirecovery.info" ascii wide
        $website2 = "https://contirecovery.best" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}
