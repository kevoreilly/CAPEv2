rule CoreBot {
    meta:
        author = "ditekSHen"
        description = "Detects CoreBot"
        cape_type = "CoreBot Payload"
    strings:
        $f1 = "core.cert_fp" fullword ascii
        $f2 = "core.crash_handler" fullword ascii
        $f3 = "core.delay" fullword ascii
        $f4 = "core.guid" fullword ascii
        $f5 = "core.inject" fullword ascii
        $f6 = "core.installed_file" fullword ascii
        $f7 = "core.plugins_dir" fullword ascii
        $f8 = "core.plugins_key" fullword ascii
        $f9 = "core.safe_mode" fullword ascii
        $f10 = "core.server" fullword ascii
        $f11 = "core.servers" fullword ascii
        $f12 = "core.test_env" fullword ascii
        $f13 = "core.vm_detect" fullword ascii
        $f14 = "core.vm_detect_skip" fullword ascii
        $s1 = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko" fullword wide
        $s2 = "\\Microsoft\\Windows\\AppCache" wide
        $s3 = "crash_flag" fullword wide
        $s4 = "container.dat" fullword wide
        $s5 = "INJECTED" fullword ascii
        $s6 = "tmp.delete_file" fullword ascii
        // variant
        $x1 = "CoreBot v" wide
        $x2 = "BotName" fullword ascii
        $x3 = "RunBotKiller" fullword ascii
        $x4 = "botv" fullword ascii
        $x5 = "\\CoreBot\\CoreBot\\obj\\" ascii
        $v1_1 = "newtask" fullword wide
        $v1_2 = "drivers\\etc\\hosts" fullword wide
        $v1_3 = "/C schtasks /create /tn \\" wide
        $v1_4 = "/st 00:00 /du 9999:59 /sc once /ri 1 /f" wide
        $v1_5 = "AntivirusInstalled" fullword ascii
        $v1_6 = "payload" fullword ascii
        $v1_7 = "DownloadFile" fullword ascii
        $v1_8 = "RemoveFile" fullword ascii
        $v1_9 = "AutoRunName" fullword ascii
        $v1_10 = "EditHosts" fullword ascii
        $v1_11 = /127\.0\.0\.1 (avast|mcafee|eset|avira|bitdefender|bullguard|safebrowse)\.com/ fullword wide
        $cnc1 = "&os=" fullword wide
        $cnc2 = "&pv=" fullword wide
        $cnc3 = "&ip=" fullword wide
        $cnc4 = "&cn=" fullword wide
        $cnc5 = "&lr=" fullword wide
        $cnc6 = "&ct=" fullword wide
        $cnc7 = "&bv=" fullword wide
        $cnc8 = "&op=" fullword wide
        $cnc9 = "&td=" fullword wide
        $cnc10 = "&uni=" fullword wide
    condition:
        uint16(0) == 0x5a4d and (5 of ($f*) or all of ($s*) or (3 of ($s*) and 2 of ($f*)) or 3 of ($x*) or 8 of ($v1*) or (4 of ($cnc*) and 4 of ($v1*)) or 12 of them)
}
