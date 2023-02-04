rule AcridRain {
    meta:
        author = "ditekshen"
        description = "AcidRain stealer payload"
        cape_type = "AcidRain payload"
    strings:
        $s1 = { 43 6f 6f 6b 69 65 73 (5c|2e) }
        $s2 = { 74 65 6d 70 6c 6f 67 69 ?? }
        $s3 = { 74 65 6d 70 50 ?? 68 }
        $s4 = "Connecting to hostname: %s%s%s" fullword ascii
        $s5 = "Found bundle for host %s: %p [%s]" fullword ascii
        $s6 = "encryptedUsernamencryptedPassworERROR Don't copy string" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
