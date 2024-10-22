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
