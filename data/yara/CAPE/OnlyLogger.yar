rule OnlyLogger {
    meta:
        author = "ditekSHen"
        description = "Detects OnlyLogger loader variants"
        cape_type = "OnlyLogger Loader"
    strings:
        $s1 = { 45 6c 65 76 61 74 65 64 00 00 00 00 4e 4f 54 20 65 6c 65 76 61 74 65 64 }
        $s2 = "\" /f & erase \"" ascii
        $s3 = "/c taskkill /im \"" ascii
        $s4 = "KILLME" fullword ascii
        $s5 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
        $gn = ".php?pub=" ascii
        $ip = /\/1[a-z0-9A-Z]{4,5}/ fullword ascii
        $h1 = "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1" fullword ascii
        $h2 = "Accept-Language: ru-RU,ru;q=0.9,en;q=0.8" fullword ascii
        $h3 = "Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1" fullword ascii
        $h4 = "Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0" fullword ascii
        $h5 = "Content-Type: application/x-www-form-urlencoded" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (#ip > 5 and ($gn or 3 of ($s*) or all of ($h*))) or (all of ($h*) and 3 of ($s*)))
}
