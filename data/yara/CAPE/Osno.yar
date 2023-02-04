rule Osno {
    meta:
      author = "ditekshen"
      description = "Osno infostealer payload"
      cape_type = "Osno payload"
    strings:
        $s1 = ".HolyGate+<>c+<<FinalBoss>" ascii
        $s2 = /Osno(Keylogger|Stealer|Ransom)/ wide
        $s3 = "password,executeWebhook('Account credentials" wide
        $s4 = "-Name Osno -PropertyType" wide
        $s5 = "process.env.hook" ascii
        $s6 = "Stealer.JSON.JsonValue" ascii
        $s7 = "<DetectBrowserss>b_" ascii
        $s8 = "<TryGetDiscordPath>b_" ascii
        $s9 = "antiVM" fullword ascii
        $s10 = "downloadurl" fullword ascii
        $s11 = "set_sPassword" fullword ascii

        $txt0 = "{0} {1} .txt" fullword wide
        $txt1 = "\\ScanningNetworks.txt" fullword wide
        $txt2 = "\\SteamApps.txt" fullword wide
        $txt3 = "-ErrorsLogs.txt" fullword wide
        $txt4 = "-keylogs.txt" fullword wide
        $txt5 = "Hardware & Soft.txt" fullword wide

        $cnc0 = "/csharp/" ascii wide
        $cnc1 = "token=" ascii wide
        $cnc2 = "&timestamp=" ascii wide
        $cnc3 = "&session_id=" ascii wide
        $cnc4 = "&aid=" ascii wide
        $cnc5 = "&secret=" ascii wide
        $cnc6 = "&api_key" ascii wide
        $cnc7 = "&session_key=" ascii wide
        $cnc8 = "&type=" ascii wide
    condition:
        (uint16(0) == 0x5a4d and (6 of ($s*) or 4 of ($txt*) or (4 of ($s*) and 2 of ($txt*)))) or (7 of ($cnc*))
}
