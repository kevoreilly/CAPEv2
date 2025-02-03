rule AsyncRAT_kingrat {
    meta:
        author = "jeFF0Falltrades"
        cape_type = "AsyncRAT Payload"

    strings:
        $str_async = "AsyncClient" wide ascii nocase
        $str_aes_exc = "masterKey can not be null or empty" wide ascii
        $str_schtasks = "schtasks /create /f /sc onlogon /rl highest" wide ascii
        $byte_aes_key_base = { 7E [3] 04 73 [3] 06 80 }
        $byte_aes_salt_base = { BF EB 1E 56 FB CD 97 3B B2 19 }
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }
        $patt_config = { 72 [3] 70 80 [3] 04 }

        $dcrat_1 = "dcrat" wide ascii nocase
        $dcrat_2 = "qwqdan" wide ascii
        $dcrat_3 = "YW1zaS5kbGw=" wide ascii
        $dcrat_4 = "VmlydHVhbFByb3RlY3Q=" wide ascii
        $dcrat_5 = "save_Plugin" wide ascii

        $ww2 = "WorldWindClient" wide fullword nocase
        $ww3 = "WorldWindStealer" wide fullword nocase
        $ww4 = "*WorldWind Pro - Results:*" wide fullword nocase
        $ww5 = /WorldWind(\s)?Stealer/ ascii wide

        $prynt = /Prynt(\s)?Stealer/ ascii wide

    condition:
        (not any of ($dcrat*) and not any of ($ww*) and not $prynt) and 6 of them and #patt_config >= 10
}

rule StormKitty {
    meta:
        author = "ditekSHen"
        description = "StormKitty infostealer payload"
        cape_type = "StormKitty Payload"
    strings:
        $x1 = "\\ARTIKA\\Videos\\Chrome-Password-Recovery" ascii
        $x2 = "https://github.com/LimerBoy/StormKitty" fullword ascii
        $x3 = "StormKitty" fullword ascii
        $s1 = "GetBSSID" fullword ascii
        $s2 = "GetAntivirus" fullword ascii
        $s3 = "C:\\Users\\Public\\credentials.txt" fullword wide
        $s4 = "^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$" fullword wide
        $s5 = "BCrypt.BCryptGetProperty() (get size) failed with status code:{0}" fullword wide
        $s6 = "\"encrypted_key\":\"(.*?)\"" fullword wide

        $ww2 = "WorldWindClient" wide fullword nocase
        $ww3 = "WorldWindStealer" wide fullword nocase
        $ww4 = "*WorldWind Pro - Results:*" wide fullword nocase
        $ww5 = /WorldWind(\s)?Stealer/ ascii wide

        $prynt = /Prynt(\s)?Stealer/ ascii wide

    condition:
        uint16(0) == 0x5a4d and (not any of ($ww*) and not $prynt) and (2 of ($x*) or 5 of ($s*) or (3 of ($s*) and 1 of ($x*)))
}


rule WorldWind {
    meta:
        author = "ditekSHen"
        description = "Detects WorldWind infostealer"
        cape_type = "WorldWind Payload"
    strings:
        $c1 = /WorldWind(\s)?Stealer/ ascii wide
        $x2 = "@FlatLineStealer" ascii wide
        $x3 = "@CashOutGangTalk" ascii wide
        $m1 = ".Passwords.Targets." ascii
        $m2 = ".Modules.Keylogger" ascii
        $m3 = ".Modules.Clipper" ascii
        $m4 = ".Modules.Implant" ascii
        $s1 = "--- Clipper" wide
        $s2 = "Downloading file: \"{file}\"" wide
        $s3 = "/bot{0}/getUpdates?offset={1}" wide
        $s4 = "send command to bot!" wide
        $s5 = " *Keylogger " fullword wide
        $s6 = "*Stealer" wide
        $s7 = "Bot connected" wide
    condition:
        uint16(0) == 0x5a4d and 1 of ($c*) and (1 of ($x*) or 2 of ($m*) or 3 of ($s*))
}


rule Prynt {
    meta:
        author = "ditekSHen"
        description = "Detects Prynt infostealer"
        cape_type = "Prynt Payload"
    strings:
        $c1 = /Prynt(\s)?Stealer/ ascii wide
        $x2 = "@FlatLineStealer" ascii wide
        $x3 = "@CashOutGangTalk" ascii wide
        $m1 = ".Passwords.Targets." ascii
        $m2 = ".Modules.Keylogger" ascii
        $m3 = ".Modules.Clipper" ascii
        $m4 = ".Modules.Implant" ascii
        $s1 = "--- Clipper" wide
        $s2 = "Downloading file: \"{file}\"" wide
        $s3 = "/bot{0}/getUpdates?offset={1}" wide
        $s4 = "send command to bot!" wide
        $s5 = " *Keylogger " fullword wide
        $s6 = "*Stealer" wide
        $s7 = "Bot connected" wide
    condition:
        uint16(0) == 0x5a4d and 1 of ($c*) and (1 of ($x*) or 2 of ($m*) or 3 of ($s*))
}


rule XWorm {
    meta:
        author = "ditekSHen"
        description = "Detects XWorm"
        cape_type = "XWorm Payload"
    strings:
        $x1 = "XWorm " wide nocase
        $x2 = /XWorm\s(V|v)\d+\.\d+/ fullword wide
        $s1 = "RunBotKiller" fullword wide
        $s2 = "XKlog.txt" fullword wide
        $s3 = /(shell|reg)fuc/ fullword wide
        $s4 = "closeshell" fullword ascii
        $s5 = { 62 00 79 00 70 00 73 00 73 00 00 ?? 63 00 61 00 6c 00 6c 00 75 00 61 00 63 00 00 ?? 73 00 63 00 }
        $s6 = { 44 00 44 00 6f 00 73 00 54 00 00 ?? 43 00 69 00 6c 00 70 00 70 00 65 00 72 00 00 ?? 50 00 45 00 }
        $s7 = { 69 00 6e 00 6a 00 52 00 75 00 6e 00 00 ?? 73 00 74 00 61 00 72 00 74 00 75 00 73 00 62 }
        $s8 = { 48 6f 73 74 00 50 6f 72 74 00 75 70 6c 6f 61 64 65 72 00 6e 61 6d 65 65 65 00 4b 45 59 00 53 50 4c 00 4d 75 74 65 78 78 00 }
        $v2_1 = "PING!" fullword wide
        $v2_2 = "Urlhide" fullword wide
        $v2_3 = /PC(Restart|Shutdown)/ fullword wide
        $v2_4 = /(Start|Stop)(DDos|Report)/ fullword wide
        $v2_5 = /Offline(Get|Keylogger)/ wide
        $v2_6 = "injRun" fullword wide
        $v2_7 = "Xchat" fullword wide
        $v2_8 = "UACFunc" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and (3 of ($s*) or 3 of ($v2*))) or 6 of them)
}

rule xworm_kingrat {
    meta:
        author = "jeFF0Falltrades"
        cape_type = "XWorm payload"
    strings:
        $str_xworm = "xworm" wide ascii nocase
        $str_xwormmm = "Xwormmm" wide ascii
        $str_xclient = "XClient" wide ascii
        $str_default_log = "\\Log.tmp" wide ascii
        $str_create_proc = "/create /f /RL HIGHEST /sc minute /mo 1 /t" wide ascii
        $str_ddos_start = "StartDDos" wide ascii
        $str_ddos_stop = "StopDDos" wide ascii
        $str_timeout = "timeout 3 > NUL" wide ascii
        $byte_md5_hash = { 7e [3] 04 28 [3] 06 6f }
        $patt_config = { 72 [3] 70 80 [3] 04 }
    condition:
        5 of them and #patt_config >= 7
}

rule DCRat {
    meta:
        author = "ditekSHen"
        description = "DCRat payload"
        cape_type = "DCRat Payload"
    strings:
        // DCRat
        $dc1 = "DCRatBuild" ascii
        $dc2 = "DCStlr" ascii
        $x1 = "px\"><center>DCRat Keylogger" wide
        $x2 = "DCRat-Log#" wide
        $x3 = "DCRat.Code" wide
        $string1 = "CaptureBrowsers" fullword ascii
        $string2 = "DecryptBrowsers" fullword ascii
        $string3 = "Browsers.IE10" ascii
        $string4 = "Browsers.Chromium" ascii
        $string5 = "WshShell" ascii
        $string6 = "SysMngmts" fullword ascii
        $string7 = "LoggerData" fullword ascii
        // DCRat Plugins/Libraries
        $plugin = "DCRatPlugin" fullword ascii
        // AntiVM
        $av1 = "AntiVM" ascii wide
        $av2 = "vmware" fullword wide
        $av3 = "VirtualBox" fullword wide
        $av4 = "microsoft corporation" fullword wide
        $av5 = "VIRTUAL" fullword wide
        $av6 = "DetectVirtualMachine" fullword ascii
        $av7 = "Select * from Win32_ComputerSystem" fullword wide
        // Plugin_AutoStealer, Plugin_AutoKeylogger
        $pl1 = "dcratAPI" fullword ascii
        $pl2 = "dsockapi" fullword ascii
        $pl3 = "file_get_contents" fullword ascii
        $pl4 = "classthis" fullword ascii
        $pl5 = "typemdt" fullword ascii
        $pl6 = "Plugin_AutoStealer" ascii wide
        $pl7 = "Plugin_AutoKeylogger" ascii wide
        // variant
        $v1 = "Plugin couldn't process this action!" wide
        $v2 = "Unknown command!" wide
        $v3 = "PLUGINCONFIGS" wide
        $v4 = "Saving log..." wide
        $v5 = "~Work.log" wide
        $v6 = "MicrophoneNum" fullword wide
        $v7 = "WebcamNum" fullword wide
        $v8 = "%SystemDrive% - Slow" wide
        $v9 = "%UsersFolder% - Fast" wide
        $v10 = "%AppData% - Very Fast" wide
        $v11 = /<span style=\"color: #F85C50;\">\[(Up|Down|Enter|ESC|CTRL|Shift|Win|Tab|CAPSLOCK: (ON|OFF))\]<\/span>/ wide
        $px1 = "[Browsers] Scanned elements: " wide
        $px2 = "[Browsers] Grabbing cookies" wide
        $px3 = "[Browsers] Grabbing passwords" wide
        $px4 = "[Browsers] Grabbing forms" wide
        $px5 = "[Browsers] Grabbing CC" wide
        $px6 = "[Browsers] Grabbing history" wide
        $px7 = "[StealerPlugin] Invoke: " wide
        $px8 = "[Other] Grabbing steam" wide
        $px9 = "[Other] Grabbing telegram" wide
        $px10 = "[Other] Grabbing discord tokens" wide
        $px11 = "[Other] Grabbing filezilla" wide
        $px12 = "[Other] Screenshots:" wide
        $px13 = "[Other] Clipboard" wide
        $px14 = "[Other] Saving system information" wide
    condition:
        uint16(0) == 0x5a4d and (all of ($dc*) or all of ($string*) or 2 of ($x*) or 6 of ($v*) or 5 of ($px*)) or ($plugin and (4 of ($av*) or 5 of ($pl*)))
}

rule dcrat_kingrat {
    meta:
        author = "jeFF0Falltrades"
        cape_type = "DCRat Payload"
    strings:
        $venom_1 = "VenomRAT" wide ascii nocase
        $venom_2 = "HVNC_REPLY_MESSAGE" wide ascii
        $str_aes_exc = "masterKey can not be null or empty" wide ascii
        $str_b64_amsi = "YW1zaS5kbGw=" wide ascii
        $str_b64_virtual_protect = "VmlydHVhbFByb3RlY3Q=" wide ascii
        $str_dcrat = "dcrat" wide ascii nocase
        $str_plugin = "save_Plugin" wide ascii
        $str_qwqdan = "qwqdan" wide ascii
        $byte_aes_key_base = { 7E [3] 04 73 [3] 06 80 }
        $patt_config = { 72 [3] 70 80 [3] 04 }
        $patt_verify_hash = { 7e [3] 04 6f [3] 0a 6f [3] 0a 74 [3] 01 }

    condition:
        (not any of ($venom*)) and 5 of them and #patt_config >= 10
}

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
