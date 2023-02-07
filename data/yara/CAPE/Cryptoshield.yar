rule Cryptoshield
{
    meta:
        author = "kevoreilly"
        description = "Cryptoshield Payload"
        cape_type = "Cryptoshield Payload"
    strings:
        $a1 = "CRYPTOSHIELD." wide
        $a2 = "Click on Yes in the next window for restore work explorer" wide
        $a3 = "r_sp@india.com - SUPPORT"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
