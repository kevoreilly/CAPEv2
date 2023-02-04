rule HawkEyev9 {
    meta:
        author = "ditekshen"
        description = "HawkEye v9 Payload"
        cape_type = "HawkEyev9 Payload"
    strings:
        $id1 = "HawkEye Keylogger - Reborn v9 - {0} Logs - {1} \\ {2}" wide
        $id2 = "HawkEye Keylogger - Reborn v9{0}{1} Logs{0}{2} \\ {3}{0}{0}{4}" wide
        $str1 = "_PasswordStealer" ascii
        $str2 = "_KeyStrokeLogger" ascii
        $str3 = "_ScreenshotLogger" ascii
        $str4 = "_ClipboardLogger" ascii
        $str5 = "_WebCamLogger" ascii
        $str6 = "_AntiVirusKiller" ascii
        $str7 = "_ProcessElevation" ascii
        $str8 = "_DisableCommandPrompt" ascii
        $str9 = "_WebsiteBlocker" ascii
        $str10 = "_DisableTaskManager" ascii
        $str11 = "_AntiDebugger" ascii
        $str12 = "_WebsiteVisitorSites" ascii
        $str13 = "_DisableRegEdit" ascii
        $str14 = "_ExecutionDelay" ascii
        $str15 = "_InstallStartupPersistance" ascii
    condition:
        int16(0) == 0x5a4d and (1 of ($id*) or 5 of ($str*))
}
