rule PikaBot
{
    meta:
        author = "kevoreilly"
        description = "PikaBot anti-vm bypass"
        cape_options = "bp0=$setz+28,action0=skip,count=1"
        hash = "59f42ecde152f78731e54ea27e761bba748c9309a6ad1c2fd17f0e8b90f8aed1"
    strings:
        $setz = {83 FB 01 74 06 43 83 FB 06 7C ?? 8B 84 9D [2] FF FF 33 DB 33 C1 39 85 [2] FF FF 0F 95 C3 EB 06}
    condition:
        uint16(0) == 0x5A4D and all of them
}
