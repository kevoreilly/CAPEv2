rule DanaBot {
    meta:
        author = "ditekSHen"
        description = "Detects DanaBot variants"
        cape_type = "DanaBot Payload"
    strings:
        $s1 = "ms ie ftp passwords" fullword wide
        $s2 = "CookieEntryEx_" fullword wide
        $s3 = "winmgmts:\\\\localhost\\root\\cimv2" fullword wide
        $s4 = "S-Password.txt" fullword wide
        $s5 = "del_ini://Main|Password|" fullword wide
        $s6 = "cmd.exe /c start chrome.exe --no-sandbox" wide
        $s7 = "cmd.exe /c start firefox.exe -no-remote" wide
        $s8 = "\\rundll32.exe shell32.dll,#" wide
        $s9 = "S_Error:TORConnect" wide
        $s10 = "InjectionProcess" fullword ascii
        $s11 = "proxylogin" fullword wide
        $s12 = "\\FS_Morff\\FS_Temp\\" wide
        $ds1 = "C:\\Windows\\System32\\rundll32.exe" fullword wide
        $ds2 = "PExtended4" fullword ascii
        $ds3 = "%s-%s" fullword wide
        $ds4 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF0123456789ABCDEF" fullword wide
        //$o1 = { 55 8b ec 33 c0 55 68 d7 60 4f 00 64 ff 30 64 89 }
        //$o2 = { e8 45 ec f0 ff e8 3c e2 f0 ff 68 00 04 00 00 e8 }
        //$o3 = { e8 98 3a f2 ff 84 c0 74 0a 8d 44 24 0c 50 e8 fe }
        //$o4 = { ba 80 d7 4f 00 a1 54 90 4f 00 e8 7e 4a f1 ff e9 }
        //$o5 = { 80 bc 24 4a 01 00 00 01 75 14 ba 80 d7 4f 00 a1 }
        //$o6 = { ba 80 d7 4f 00 a1 80 8f 4f 00 e8 4c 4a f1 ff e9 }
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or 3 of ($ds*))
}
