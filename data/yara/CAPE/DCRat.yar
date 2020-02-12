rule DCRat {
    meta:
        author = "ditekshen"
        description = "DCRat payload"
        cape_type = "DCRat payload"
    strings:
        // DCRat
        $dc1 = "DCRatBuild" ascii
        $dc2 = "DCStlr" ascii

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
        
    condition:
        uint16(0) == 0x5a4d and (all of ($dc*) or all of ($string*)) or ($plugin and (4 of ($av*) or 5 of ($pl*)))
}
