rule Kutaki {
    meta:
        author = "ditekSHen"
        description = "Detects Kutaki"
        cape_type = "Kutaki Payload"
    strings:
        $x1 = "AASEaHR0cDovL29qb3JvYmlhLmNsdWIvbGFwdG9wL2xhcHRvcC5waHA" ascii
        $x2 = "aHR0cDovL3RlcmViaW5uYWhpY2MuY2x1Yi9zZWMva29vbC50eHQ" ascii
        $s1 = "wewqeuuiwe[XXXXXXX]" ascii
        $s2 = "alt|aHR0cD" ascii
        $s3 = "<rdf:Description about='uuid:fb761dc9-9daf-11d9-9a32-fcf1da45dca2'" ascii
        $s4 = "<rdf:Description about='uuid:0ab54f47-96d6-11d9-a59c-cbc93330e07e'" ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 1 of ($s*)) or (all of ($s*)))
}
