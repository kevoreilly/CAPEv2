rule Kovter
{
    meta:
        author = "kevoreilly"
        description = "Kovter Payload"
        cape_type = "Kovter Payload"
    strings:
        $a1 = "chkok"
        $a2 = "k2Tdgo"
        $a3 = "13_13_13"
        $a4 = "Win Server 2008 R2"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
