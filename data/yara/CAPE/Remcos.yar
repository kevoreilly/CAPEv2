rule Remcos
{
    meta:
        author = "kevoreilly"
        description = "Remcos Payload"
        cape_type = "Remcos Payload"
    strings:
        $name  = "Remcos" nocase
        $time   = "%02i:%02i:%02i:%03i"
        $crypto = {0F B6 [1-7] 8B 45 08 [0-2] 8D 34 07 8B 01 03 C2 8B CB 99 F7 F9 8A 84 95 ?? ?? FF FF 30 06 47 3B 7D 0C 72}
    condition:
        uint16(0) == 0x5A4D and all of ($*)
}
