rule Jaff
{
    meta:
        author = "kevoreilly"
        description = "Jaff Payload"
        cape_type = "Jaff Payload"
    strings:
        $a1 = "CryptGenKey"
        $a2 = "353260540318613681395633061841341670181307185694827316660016508"
        $b1 = "jaff"
        $b2 = "2~1c0q4t7"
    condition:
        uint16(0) == 0x5A4D and (any of ($a*) ) and (1 of ($b*))
}
