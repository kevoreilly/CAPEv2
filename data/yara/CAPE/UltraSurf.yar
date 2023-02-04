rule UltraSurf {
    meta:
        author = "ditekSHen"
        description = "Detects UltraSurf / Ultrareach PUA"
        cape_type = "UltraSurf PUA Payload"
    strings:
        $s1 = "Ultrareach Internet Corp." ascii
        $s2 = "UltrasurfUnionRectUrlFixupWUse Proxy" ascii
        $s3 = "Ultrasurf UnlockFileUrlEscapeWUser-Agent" ascii wide
        $s4 = "Ultrasurf0#" ascii
        $m1 = "main.bindata_read" fullword ascii
        $m2 = "main.icon64_png" fullword ascii
        $m3 = "main.setProxy" fullword ascii
        $m4 = "main.openbrowser" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or (all of ($m*) and 1 of ($s*)))
}
