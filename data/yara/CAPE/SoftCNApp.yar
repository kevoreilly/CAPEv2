rule SoftCNApp {
    meta:
        author = "ditekSHen"
        description = "Detects SoftCNApp"
        cape_type = "SoftCNApp Payload"
    strings:
        $s1 = "\\\\.\\PIPE\\SOC%d" fullword ascii
        $s2 = "Mozilla/5.0 (Windows NT 6.1)" fullword ascii
        $s3 = "Param: sl=%d; sl=%d; sl=%d; sl=%d; sl=%d;" fullword ascii
        $s4 = ".?AVCHPPlugin@@" fullword ascii
        $s5 = ".?AVCHPCmd@@" fullword ascii
        $s6 = ".?AVCHPExplorer@@" fullword ascii
        $s7 = "%s\\svchost.exe -O" fullword wide
        $s8 = "\"%s\\%s\" -P" fullword ascii
        $n1 = "45.63.58.34" fullword ascii
        $n2 = "127.0.0.1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or (all of ($n*) and 2 of ($s*)))
}
