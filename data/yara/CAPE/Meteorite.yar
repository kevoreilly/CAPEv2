rule Meteorite {
    meta:
        author = "ditekSHen"
        description = "Detects Meteorite Downloader"
        cape_type = "Meteorite Downloader Payload"
    strings:
        $x1 = "MeteoriteDownloader" fullword ascii wide
        $x2 = "Meteorite Downloader" fullword ascii wide
        $x3 = "Meteorite Downloader v" wide
        $s1 = "regwrite" fullword wide
        $s2 = "urlmon" fullword ascii
        $s3 = "wscript.shell" fullword wide
        $s4 = "modMain" fullword ascii
        $s5 = "VBA6.DLL" fullword ascii
        $s6 = "^_http" ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or (5 of ($s*)))
}
