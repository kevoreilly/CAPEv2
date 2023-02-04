rule Owowa {
    meta:
        author = "ditekSHen"
        description = "Detects Owowa"
        cape_type = "Owowa Payload"
    strings:
        $u1 = "jFuLIXpzRdateYHoVwMlfc" fullword ascii wide
        $u2 = "Fb8v91c6tHiKsWzrulCeqO" fullword ascii wide
        $u3 = "dEUM3jZXaDiob8BrqSy2PQO1" fullword ascii wide
        $s1 = "powershell.exe" fullword wide
        $s2 = "<RSAKeyValue><Modulus>" wide
        $s3 = "HealthMailbox" fullword wide
        $s4 = "6801b573-4cdb-4307-8d4a-3d1e2842f09f" ascii
        $s5 = "<PreSend_RequestContent>b__" ascii
        $s6 = "ClearHeaders" fullword ascii
        $s7 = "get_UserHostAddress" fullword ascii
        $s8 = "ExtenderControlDesigner" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($u*) or (2 of ($u*) and 3 of ($s*)) or 6 of ($s*))
}
