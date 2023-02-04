rule Lorenz {
    meta:
        author = "ditekSHen"
        description = "Detects Lorenz ransomware"
        cape_type = "Lorenz Payload"
    strings:
        $x1 = "143.198.117.43" fullword ascii
        $x2 = "157.90.147.28" fullword ascii
        $x3 = "//kpb3ss3vwvfejd4g3gvpvqo6ad7nnmvcqoik4mxt2376yu2adlg5fwyd.onion" ascii
        $x4 = "http://lorenz" ascii
        $x5 = "\\lora\\Release\\lora.pdb" ascii
        $x6 = "--MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ" ascii
        $x7 = "/USER:'HOMEOFFICE.COM\\" ascii
        $x8 = "/USER:'Sentinel.com\\" ascii
        $s1 = "to->_What == nullptr && to->_DoFree == false" fullword wide
        $s2 = "*it == '\\0'" fullword wide
        $s3 = "process call create 'cmd.exe /c" ascii
        $s4 = "\\Control Panel\\Desktop\" /V Wallpaper /T REG_SZ /F /D" ascii
        $s5 = "HELP_SECURITY_EVENT.html" ascii
        $s6 = "<br>[+] Whats Happen?" ascii
        $s7 = /\.Lorenz\.sz\d+$/ fullword ascii
        $s8 = "TW9Vc29Db3JlV29ya2VyLmV4ZQ==" fullword ascii
        $s9 = ".Speak(\"You've been hack" ascii nocase
        $s10 = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAo" ascii
        $n1 = "ame_serv=" ascii
        $n2 = "&ip=" ascii
        $n3 = "&winver=Windows" ascii
        $n4 = "&list_drive=" ascii
        $n5 = "&file=" ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or 8 of ($s*) or (4 of ($n*) and 2 of them) or (1 of ($x*) and 6 of them))
}
