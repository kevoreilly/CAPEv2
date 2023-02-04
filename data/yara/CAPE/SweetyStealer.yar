rule SweetyStealer {
    meta:
        author = "ditekSHen"
        description = "Detects SweetyStealer"
        cape_type = "SweetyStealer Payload"
    strings:
        $s1 = "SWEETY STEALER" wide
        $s2 = "\\SWEETYLOG.zip" fullword wide
        $s3 = "\\SWEETY STEALER\\SWEETY\\" ascii
        $s4 = "\\Sweety" fullword wide
        $s5 = "SWEETYSTEALER." ascii
        $s6 = "in Virtual Environment, so we prevented stealing" wide
        $s7 = ":purple_square:" wide
        $f1 = "<GetDomainDetect>b__" ascii
        $f2 = "<GetAllProfiles>b__" ascii
        $f3 = "<ProcessExtraFieldZip64>b__" ascii
        $f4 = "<PostExtractCommandLine>k__" ascii
    condition:
        uint16(0) == 0x5a4d and 3 of ($s*) or (3 of ($f*) and 1 of ($s*))
}
