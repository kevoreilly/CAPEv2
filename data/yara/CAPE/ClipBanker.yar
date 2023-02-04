rule ClipBanker01 {
    meta:
        author = "ditekSHen"
        description = "Detects ClipBanker infostealer"
        cape_type = "ClipBanker01 Payload"
    strings:
        $s1 = "Clipper" fullword wide
        $s2 = "Ushell" fullword wide
        $s3 = "Banker" fullword wide
        $s4 = "ClipPurse" fullword wide nocase
        $s5 = "SelfClip" fullword wide
        $s6 = "Cliper" fullword wide
        $s7 = "FHQD4313-33DE-489D-9721-6AFF69841DEA" fullword wide
        $s8 = "Remove.bat" fullword wide
        $s9 = "\\w{1}\\d{12}" fullword wide
        $s10 = "SELECT * FROM Win32_ComputerSystem" fullword wide
        $s11 = "red hat" fullword wide
        $s12 = { 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00
                 2e 00 65 00 78 00 65 00 00 ?? 2f 00 63 00 72 00
                 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00
                 20 00 00 ?? 20 00 2f 00 6d 00 6f 00 20 00 00 ??
                 20 00 2f 00 72 00 6c 00 20 00 00 ?? 20 00 2f 00
                 74 00 6e 00 20 00 00 ?? 20 00 2f 00 74 00 72 00
                 20 00 00 ?? 20 00 ?? 00 ?? 00 00 ?? 2f 00 64 00
                 65 00 6c 00 65 00 74 00 65 00 20 00 2f 00 74 00
                 6e }
        $s13 = "ClipChanger" fullword ascii
        $s14 = "CheckVirtual" fullword ascii
        $s15 = "InjReg" fullword ascii
        $s16 = "SuicideFile" fullword ascii
        $s17 = "HideFile" fullword ascii
        $s18 = "AntiVm" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 7 of them
}

rule ClipBanker02 {
    meta:
        author = "ditekSHen"
        description = "Detects ClipBanker infostealer"
        cape_type = "ClipBanker02 Payload"
    strings:
        $x1 = "\\Allcome\\Source code\\Clipper\\" ascii nocase
        $x2 = "\\cleaper\\Release\\cleaper.pdb" ascii nocase
        $v1_1 = "&username=" fullword ascii
        $v1_2 = "/card.php?data=" fullword ascii
        $v1_3 = "/Create /tn MicrosoftDriver /sc MINUTE /tr" fullword ascii
        $v1_4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0" fullword ascii
        $v1_5 = "/API/Clipper/ykesqk0o.php?cf6zrlhn=" fullword ascii
        $v1_6 = "&di7ztth6=" fullword ascii
        $v1_7 = "/API/Clipper/hr627gzk.php?v6etwxo5=" fullword ascii
        $v2_1 = "bitcoincash:" fullword ascii
        $v2_2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii
        $re1 = "^[0-9]{16}$" fullword ascii
        $re2 = "^[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" fullword ascii
        $re3 = "^\\d{2}\\D\\d{2}" fullword ascii
        $re4 = "^[0-9]{3}" fullword ascii
        $re5 = "([\\W]?[0-9]{4}[\\W]?[0-9]{4}[\\W]?[0-9]{4}[\\W]?[0-9]{4}[\\W]?)" fullword ascii
        $re6 = "(\\d{2}\\D\\d{2})" fullword ascii
        $re7 = "(\\d{3})" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and (5 of ($v1*) or all of ($v2*))) or (3 of ($re*) and (2 of ($v1*) or 2 of ($v2*))))
}
