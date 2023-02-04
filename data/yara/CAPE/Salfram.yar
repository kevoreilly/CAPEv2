rule Salfram {
    meta:
        author = "ditekSHen"
        description = "Detects Salfram executables"
        cape_type = "Salfram Payload"
    strings:
        $s1 = "!This Salfram cannot be run in DOS mode." fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
