rule M00nD3v {
    meta:
        author = "ditekshen"
        description = "M00nD3v keylogger payload"
        cape_type = "M00nD3v payload"
    strings:
        $s1 = "M00nD3v Stub" ascii wide
        $s2 = "M00nD3v{0}{1} Logs{0}{2} \\ {3}{0}{0}{4}" fullword wide
        $s3 = "Anti-Keylogger Elite" wide
        $s4 = "/C TASKKILL /F /IM" wide
        $s5 = "echo.>{0}:Zone.Identifier" fullword wide
        $s6 = "> Nul & Del \"{0}\" & start \"\" \"{1}.exe\"" wide
        $s7 = "> Nul & start \"\" \"{1}.exe\"" wide
        $s8 = "Stealer" fullword wide
        $s9 = "{0}{0}++++++++++++{1} {2}++++++++++++{0}{0}" wide
        $s10 = "{4}Application: {3}{4}URL: {0}{4}Username: {1}{4}Password: {2}{4}" wide
        $s11 = "encrypted_key\":\"(?<Key>.+?)\"" wide
        $s12 = "Botkiller" fullword ascii
        $s13 = "AVKiller" fullword ascii
        $s14 = "get_pnlPawns" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 6 of them) or (9 of them)
}
