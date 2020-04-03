rule Nemty
{
    meta:
        author = "kevoreilly"
        description = "Nemty Ransomware Payload"
        cape_type = "Nemty Payload"
    strings:
        $tordir = "TorDir"
        $decrypt = "DECRYPT.txt"
        $nemty = "NEMTY"
    condition:
        uint16(0) == 0x5A4D and all of them
}
