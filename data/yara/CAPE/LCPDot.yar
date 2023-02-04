rule LCPDot {
    meta:
        author = "ditekSHen"
        description = "Detects LCPDot. Associated with Lazarus"
        cape_type = "LCPDot Payload"
    strings:
        $s1 = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword wide
        $s2 = "Cookie: SESSID=%s" fullword ascii
        $s3 = "Cookie=Enable" fullword ascii
        $s4 = "Cookie=Enable&CookieV=%d&Cookie_Time=32" fullword ascii
        $s5 = ".?AVTShellCodeRuner@@" fullword ascii
        $s6 = ".?AVTHashEncDecoder@@" fullword ascii
        $s7 = ".?AVTWebAddressList@@" fullword ascii
        $s8 = "WinMain.dll" fullword ascii
        $s9 = "HotPlugin" wide
        $o0 = { 4c 89 6c 24 08 4c 89 34 24 44 8d 77 01 44 8d 6f }
        $o1 = { 8b f0 e8 58 34 00 00 48 8b f8 48 85 c0 74 0c 48 }
        $o2 = { c7 44 24 30 47 49 46 38 c7 44 24 34 39 61 27 00 }
    condition:
        uint16(0) == 0x5a4d and 6 of ($s*) or (all of ($o*) and 3 of ($s*))
}
