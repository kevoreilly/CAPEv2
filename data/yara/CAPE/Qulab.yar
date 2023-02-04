rule Qulab {
    meta:
        author = "ditekshen"
        description = "Qulab information stealer payload or artifacts"
        cape_type = "Qulab Payload"
    strings:
        $x1 = "QULAB CLIPPER + STEALER" ascii wide
        $x2 = "MASAD CLIPPER + STEALER" ascii wide
        $x3 = "http://teleg.run/Qulab" ascii wide
        $x4 = "http://teleg.run/jew_seller" ascii wide
        $x5 = "BUY CLIPPER + STEALER" ascii wide
        $s1 = "\\Screen.jpg" ascii wide
        $s2 = "attrib +s +h \"" ascii wide
        $s3 = "\\x86_microsoft-windows-" ascii wide
        $s4 = "\\amd64_microsoft-windows-" ascii wide
        $s5 = "Desktop TXT File" ascii wide
        $s6 = "\\AutoFills.txt" ascii wide
        $s7 = "\\CreditCards.txt" ascii wide
        $s8 = "a -y -mx9 -ssw" ascii wide
        $s9 = "\\Passwords.txt" ascii wide
        $s10 = "\\Information.txt" ascii wide
        $s11 = "\\getMe" ascii wide
    condition:
        9 of them or ((1 of ($x*) and 4 of ($s*)) or 1 of ($x*))
}
