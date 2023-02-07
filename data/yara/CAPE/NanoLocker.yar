rule NanoLocker
{
    meta:
        author = "kevoreilly"
        description = "NanoLocker Payload"
        cape_type = "NanoLocker Payload"
    strings:
        $a1 = "NanoLocker"
        $a2 = "$humanDeadline"
        $a3 = "Decryptor.lnk"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
