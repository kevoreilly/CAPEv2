rule Kimsuky {
    meta:
        author = "ditekshen"
        description = "Detects Kimsuky backdoor"
        cape_type = "Kimsuky Payload"
    strings:
        $s1 = "Win%d.%d.%dx64" fullword ascii
        $s2 = ".zip" fullword ascii
        $s3 = ".enc" fullword ascii
        $s4 = "&p2=a" fullword ascii
        $s5 = "Content-Disposition: form-data; name=\"binary\"; filename=\"" fullword ascii
        $s6 = "%s/?m=a&p1=%s&p2=%s-%s-v%d" fullword ascii
        $s7 = "/?m=b&p1=" fullword ascii
        $s8 = "/?m=c&p1=" fullword ascii
        $s9 = "/?m=d&p1=" fullword ascii
        $s10 = "http://%s/%s/?m=e&p1=%s&p2=%s&p3=%s" fullword ascii
        $s11 = "taskkill.exe /im iexplore.exe /f" fullword ascii
        $s12 = "GetParent" fullword ascii
        $s13 = "DllRegisterServer" fullword ascii
        $dll1 = "AutoUpdate.dll" fullword ascii
        $dll2 = "dropper-ie64.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($dll*) and 7 of ($s*)) or (11 of ($*)))
}
