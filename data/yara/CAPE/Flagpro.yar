rule Flagpro {
    meta:
        author = "ditekSHen"
        description = "Detects Flagpro"
        cape_type = "Flagpro Payload"
    strings:
        $s1 = "download...." fullword ascii
        $s2 = "~MYTEMP" fullword wide
        $s3 = ".?AVCV20_LoaderApp@@" fullword ascii
        $s4 = ".?AVCV20_LoaderDlg@@" fullword ascii
        $s5 = "ExecYes" fullword ascii
        $s6 = /<BODY ID=CV\d+_LoaderDlg BGCOLOR=/ ascii
        $n1 = "://139.162.87.180" wide
        $n2 = "://172.104.109.217" wide
        $n3 = "://org.misecure.com/index.html" wide
        $b1 = /(get all|click|close|maybe|get_outerHTML|download\d) (finished|pass|ok|windows|failed)!/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of ($s*) or (1 of ($n*) and (2 of ($s*) or 1 of ($b*))) or (2 of ($s*) and 1 of ($b*))
}
