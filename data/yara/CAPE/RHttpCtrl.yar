rule RHttpCtrl {
    meta:
        author = "ditekshen"
        description = "RHttpCtrl backdoor payload"
        cape_type = "RHttpCtrl payload"
    strings:
        $s1 = "%d_%04d%02d%02d%02d%02d%02d." ascii
        $s2 = "ver=%s&id=%06d&type=" ascii
        $s3 = "ver=%d&id=%s&random=%d&" ascii
        $s4 = "id=%d&output=%s" ascii
        $s5 = "Error:WinHttpCrackUrl failed!/n" ascii
        $s6 = "Error:SendRequest failed!/n" ascii
        $s7 = ".exe a %s %s" ascii
        $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0" fullword wide
        $pdb = "\\WorkSources\\RHttpCtrl\\Server\\Release\\svchost.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or ($pdb and 2 of ($s*)))
}
