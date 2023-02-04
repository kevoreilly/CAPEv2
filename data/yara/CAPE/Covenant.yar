rule GruntStager {
     meta:
        author = "ditekSHen"
        description = "Detects Covenant Grunt Stager"
        cape_type = "GruntStager Payload"
    strings:
        $x1 = "VXNlci1BZ2VudA" ascii wide
        $x2 = "cGFnZT17R1VJRH0mdj0x" ascii wide
        $x3 = "0eXBlPXtHVUlEfSZ2PTE" ascii wide
        $x4 = "tZXNzYWdlPXtHVUlEfSZ2PTE" ascii wide
        $x5 = "L2VuLXVzL" ascii wide
        $x6 = "L2VuLXVzL2luZGV4Lmh0bWw" ascii wide
        $x7 = "L2VuLXVzL2RvY3MuaHRtbD" ascii wide
        $s1 = "ExecuteStager" ascii
        $s2 = "UseCertPinning" fullword ascii
        $s3 = "FromBase64String" fullword ascii
        $s4 = "ToBase64String" fullword ascii
        $s5 = "DownloadString" fullword ascii
        $s6 = "UploadString" fullword ascii
        $s7 = "GetWebRequest" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or all of ($s*) or (1 of ($x*) and 5 of ($s*)))
}
