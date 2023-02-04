rule Baldr {
    meta:
        author = "ditekshen"
        description = "Baldr payload"
        cape_type = "Baldr payload"
    strings:
        $x1 = "BALDR VERSION : {0}" fullword wide
        $x2 = "Baldr" fullword ascii wide
        $x3 = "{0}\\{1:n}.exe" fullword wide
        $x4 = ".doc;.docx;.log;.txt;" fullword wide
        $s1 = "<GetMAC>b__" ascii
        $s2 = "<ExtractPrivateKey3>b__" ascii
        $s3 = "UploadData" fullword ascii
        $s6 = "get_NetworkInterfaceType" fullword ascii
        $s5 = "get_Passwordcheck" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and all of ($x*)) or (2 of ($x*) and 4 of ($s*))
}
