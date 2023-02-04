import "pe"

rule FatDuke {
    meta:
        author = "ditekSHen"
        description = "Detects FatDuke"
        cape_type = "FatDuke Payload"
    strings:
        $s1 = "\\\\?\\Volume" fullword ascii
        $s2 = "WINHTTP_AUTOPROXY_OPTIONS@@PAUWINHTTP_PROXY_INFO@@" ascii
        $s3 = "WINHTTP_CURRENT_USER_IE_PROXY_CONFIG@@" ascii
        $s4 = "Cannot write a Cannot find the too long string mber of records Log malfunction! Cannot create ain an invalid ra Internal sync iright function iWaitForSingleObjffsets" ascii
        $pattern = "()$^.*+?[]|\\-{},:=!" ascii
        $b64 = "eyJjb25maWdfaWQiOi" wide
        //$decoded = "{\"config_id\"" base64wide
    condition:
        //uint16(0) == 0x5a4d and (3 of ($s*) or (($b64 or $decoded) and 2 of them) or (#pattern > 3 and 2 of them))
        uint16(0) == 0x5a4d and (3 of ($s*) or ($b64 and 2 of them) or (#pattern > 3 and 2 of them))
}

rule MiniDuke {
    meta:
        author = "ditekSHen"
        description = "Detects MiniDuke"
        cape_type = "MiniDuke Payload"
    strings:
        $s1 = "DefPipe" fullword ascii
        $s2 = "term %5d" fullword ascii
        $s3 = "pid %5d" fullword ascii
        $s4 = "uptime %5d.%02dh" fullword ascii
        $s5 = "login: %s\\%s" fullword ascii
        $s6 = "Software\\Microsoft\\ApplicationManager" ascii
        $s7 = { 69 64 6c 65 ?? 00 73 74 6f 70 ?? 00 61 63 63 65 70 74 ?? 00 63 6f 6e 6e 65 63 74 ?? 00 6c 69 73 74 65 6e ?? 00 }

        $net1 = "salesappliances.com" ascii
        $net2 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36" fullword ascii
        $net3 = "http://10." ascii
        $net4 = "JiM9t8g7j8KoJkLJlKqka8dbo7q5z4v5u3o4z" ascii
        $net5 = "application/octet-stream" ascii
        $net6 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or 4 of ($net*) or 7 of them)
}

rule PolyglotDuke {
    meta:
        author = "ditekSHen"
        description = "Detects PolyGlotDuke"
        cape_type = "PolyGlotDuke Payload"
    strings:
        $s1 = { 48 b9 ff ff ff ff ff ff ff ff 51 48 23 8c 24 ?? 00 00 00 48 89 8C 24 00 00 00 00 }
        $s2 = { 56 be ff ff ff ff 56 81 e6 7f }
        $s3 = { 48 8b 05 19 ?4 4b 00 48 05 48 83 00 00 4c 8b 44 24 50 8b 54 24 48 48 8b }
        //$s4 = { 48 8B 84 24 ?? 00 00 00 48 ?? ?? 24 ?? 00 00 00 48 89 84 24 }
    condition:
        uint16(0) == 0x5a4d and (all of ($s*)) or
         (
                 2 of them and
                 pe.exports("InitSvc")
        )
}
