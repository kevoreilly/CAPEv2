rule StrifeWater {
    meta:
        author = "ditekSHen"
        description = "Detects StrifeWater RAT"
        cape_type = "StrifeWater RAT Payload"
    strings:
        $s1 = "example/1.0" fullword wide
        $s2 = "coname:" fullword ascii
        $s3 = "*elev:" fullword ascii
        $s4 = "*uname:" fullword ascii
        $s5 = "--BoundrySign" ascii
        $s6 = "000000c:\\users\\public\\libraries\\tmp.bi" ascii
        $s7 = "9c4arSBr32g6IOni" fullword ascii
        $pdb = "\\win8\\Desktop\\ishdar_win8\\" ascii
        $xn1 = "techzenspace.com" fullword wide
        $xn2 = "87.120.8.210" wide
        $xn3 = "192.168.40.27" wide
        $n1 = /RVP\/index\d+\.php/ fullword wide
        $n2 = "tid=%d&code=%s&fname=%s&apiData=%s" fullword ascii
        $n3 = "code=%s&tid=%d&fname=%s&apiData=%s" fullword ascii
        $n4 = "Content-Disposition: form-data; name=\"token\"" fullword ascii
        $n5 = "Content-Disposition: form-data; name=\"apiData\"" fullword ascii
        $n6 = "Content-Disposition: form-data; name=\"data\"; filename=\"" fullword ascii
        $n7 = "Content-Disposition: form-data; name=\"tid\"" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($xn*) or 6 of ($s*) or 6 of ($n*) or (1 of ($xn*) and 4 of them) or ($pdb and 4 of them) or (3 of ($s*) and 3 of ($n*)))
}
