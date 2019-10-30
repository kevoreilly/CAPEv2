rule Petya
{
    meta:
        author = "kevoreilly"
        description = "Petya Payload"
        cape_type = "Petya Payload"
    strings:
        $a1 = "CHKDSK is repairing sector"
        $a2 = "wowsmith123456@posteo.net"
        $a3 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" wide
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
