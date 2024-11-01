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

rule quasarrat_kingrat {
    meta:
        author = "jeFF0Falltrades"
        cape_type = "QuasarRAT Payload"
    strings:
        $str_quasar = "Quasar." wide ascii
        $str_hidden = "set_Hidden" wide ascii
        $str_shell = "DoShellExecuteResponse" wide ascii
    $str_close = "echo DONT CLOSE THIS WINDOW!" wide ascii
        $str_pause = "ping -n 10 localhost > nul" wide ascii
        $str_aes_exc = "masterKey can not be null or empty" wide ascii
        $byte_aes_key_base = { 7E [3] 04 73 [3] 06 25 }
        $byte_aes_salt_base = { BF EB 1E 56 FB CD 97 3B B2 19 }
        $byte_special_folder = { 7e 73 [4] 28 [4] 80 }
        $patt_config = { 72 [3] 70 80 [3] 04 }
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }

    condition:
        6 of them and #patt_config >= 10
}
