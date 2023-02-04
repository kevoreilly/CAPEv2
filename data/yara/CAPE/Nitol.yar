rule Nitol {
    meta:
        author = "ditekSHen"
        description = "Detects Nitol backdoor"
        cape_type = "Nitol Backdoor Payload"
    strings:
        $s1 = "%$#@!.aspGET ^&*().htmlGET" ascii
        $s2 = "Applications\\iexplore.exe\\shell\\open\\command" fullword ascii
        $s3 = "taskkill /f /im rundll32.exe" fullword ascii
        $s4 = "\\Tencent\\Users\\*.*" fullword ascii
        $s5 = "[Pause Break]" fullword ascii
        $s6 = ":]%d-%d-%d  %d:%d:%d" fullword ascii
        $s7 = "GET %s HTTP/1.1" fullword ascii
        $s8 = "GET %s%s HTTP/1.1" fullword ascii
        $s9 = "Accept-Language: zh-cn" fullword ascii
        $s10 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 5.1)" fullword ascii
        $s11 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
        $s12 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
        $w1 = ".aspGET" ascii
        $w2 = ".htmGET" ascii
        $w3 = ".htmlGET" ascii
        $domain = "www.xy999.com" fullword ascii
        $v2_1 = "loglass" fullword ascii
        $v2_2 = "rlehgs" fullword ascii
        $v2_3 = "eherrali" fullword ascii
        $v2_4 = "agesrlu" fullword ascii
        $v2_5 = "lepejagas" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or (all of ($v2*)) or ($domain and 3 of them) or (#w1 > 2 and #w2 > 2 and #w3 > 2 and 3 of ($s*)))
}
