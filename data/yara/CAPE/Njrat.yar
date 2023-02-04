rule Njrat
{
        meta:
                author = " Kevin Breen <kevin@techanarchy.net> & ditekSHen"
                ref = "http://malwareconfig.com/stats/njRat"
                maltype = "Remote Access Trojan"
                filetype = "exe"
        cape_type = "Njrat Payload"

        strings:

                $s1 = {7C 00 27 00 7C 00 27 00 7C} // |'|'|
                $s2 = "netsh firewall add allowedprogram" wide
                $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
                $s4 = "yyyy-MM-dd" wide

                $v1 = "cmd.exe /k ping 0 & del" wide
                $v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
                $v3 = "cmd.exe /c ping 0 -n 2 & del" wide

                $x1 = "netsh firewall delete allowedprogram" wide
                $x2 = "netsh firewall add allowedprogram" wide
                $x3 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 (63|6b) 00 20 00 70 00 69 00 6e 00 67 }
                $x4 = "Execute ERROR" wide
                $x5 = "Download ERROR" wide
                $x6 = "[kl]" fullword wide
        condition:
                (all of ($s*) and any of ($v*)) or (uint16(0) == 0x5a4d and 4 of ($x*))
}
