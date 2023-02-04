rule MALWARE_Win_XFiles {
    meta:
        author = "ditekSHen"
        description = "Detects X-Files infostealer (formerly BotSh1zoid)"
        cape_type = "XFiles Infostealer Payload"
    strings:
        $x1 = "\\BotSh1zoid\\" ascii
        $x2 = "\\BuildPacker.pdb" ascii
        $x3 = "\\Svc_host.pdb" ascii nocase
        $s1 = "WDefender" fullword ascii
        $s2 = "CheckDefender" fullword ascii
        $s3 = "RunPS" fullword ascii
        $s4 = "DownloadFile" fullword ascii
        $v1_1 = "<Pass encoding=\"base64\">(.*)</Pass>" wide
        $v1_2 = "Grabber\\" wide
        $v1_3 = "/log.php" wide
        $v1_4 = /Browsers\\(Logins|Cards|Cookies)/ wide
        $v1_5 = "<StealSteam>b__" ascii
        $v1_6 = "record_header_field" fullword ascii
        $v1_7 = "JavaScreenshotiptReader" fullword ascii
        $v1_8 = "HTTPDebuggerPro" wide
        $v1_9 = "IEInspector" wide
        $v1_10 = "Fiddler" wide
        $v2_1 = /get_(Cookie|Logins|Cards)Path/ fullword ascii
        $v2_2 = "get_AllScreens" fullword ascii
        $v2_3 = "{0}_{1}_{2}.zip" fullword wide
        $v2_4 = "\\Stealer" fullword wide
        $g1 = "$983a3552-4ec3-4936-bd4a-8e6fd67b4c67" fullword ascii
        $g2 = "$a5d9ca4d-400f-4e07-8c09-a916b548f2e3" fullword ascii
        $g3 = "$ebc25cf6-9120-4283-b972-0e5520d0000C" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and (3 of ($s*) or 3 of ($v1*) or 3 of ($v2*))) or 7 of ($v1*) or 3 of ($v2*) or (2 of ($g*) and 3 of them))
}
