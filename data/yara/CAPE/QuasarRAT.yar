rule QuasarRAT {
    meta:
        author = "ditekshen"
        description = "QuasarRAT payload"
        cape_type = "QuasarRAT Payload"
    strings:
        $s1 = "GetKeyloggerLogsResponse" fullword ascii
        $s2 = "GetKeyloggerLogs" fullword ascii
        $s3 = "/>Log created on" wide
        $s4 = "User: {0}{3}Pass: {1}{3}Host: {2}" wide
        $s5 = "Domain: {1}{0}Cookie Name: {2}{0}Value: {3}{0}Path: {4}{0}Expired: {5}{0}HttpOnly: {6}{0}Secure: {7}" wide
        $s6 = "grabber_" wide
        $s7 = "<virtualKeyCode>" ascii
        $s8 = "<RunHidden>k__BackingField" fullword ascii
        $s9 = "<keyboardHookStruct>" ascii
        $s10 = "add_OnHotKeysDown" ascii
        $mutex = "QSR_MUTEX_" ascii wide
        $ua1 = "Mozilla/5.0 (Windows NT 6.3; rv:48.0) Gecko/20100101 Firefox/48.0" fullword wide
        $us2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A" fullword wide
    condition:
        uint16(0) == 0x5a4d and ($mutex or (all of ($ua*) and 2 of them) or 6 of ($s*))
}
