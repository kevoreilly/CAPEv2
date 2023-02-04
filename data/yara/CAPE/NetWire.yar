rule NetWire
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net> & David Cannings & ditekSHen"
		ref = "http://malwareconfig.com/stats/NetWire"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        cape_type = "NetWire Payload"

    strings:

        $exe1 = "%.2d-%.2d-%.4d"
        $exe2 = "%s%.2d-%.2d-%.4d"
        $exe3 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
        $exe4 = "wcnwClass"
        $exe5 = "[Ctrl+%c]"
        $exe6 = "SYSTEM\\CurrentControlSet\\Control\\ProductOptions"
        $exe7 = "%s\\.purple\\accounts.xml"

        $s1 = "-w %d >nul 2>&1" ascii
        $s2 = "[Log Started]" ascii
        $s3 = "DEL /s \"%s\" >nul 2>&1" fullword ascii
        $s4 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" fullword ascii
        $s5 = ":deleteSelf" ascii
        $s6 = "%s\\%s.bat" fullword ascii

        $x1 = "SOFTWARE\\NetWire" fullword ascii
        $x2 = { 4e 65 74 57 69 72 65 00 53 4f 46 54 57 41 52 45 5c 00 }
        $var1 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
        $var2 = "filenames.txt" fullword ascii
        $var3 = "GET %s HTTP/1.1" fullword ascii
        $var4 = "[%.2d/%.2d/%d %.2d:%.2d:%.2d]" fullword ascii
        $var5 = "Host.exe" fullword ascii
        $var6 = "-m \"%s\"" fullword ascii
        $gvar1 = "HostId" fullword ascii
        $gvar2 = "History" fullword ascii
        $gvar3 = "encrypted_key" fullword ascii
        $gvar4 = "Install Date" fullword ascii
        $gvar5 = "hostname" fullword ascii
        $gvar6 = "encryptedUsername" fullword ascii
        $gvar7 = "encryptedPassword" fullword ascii

    condition:
        all of ($exe*) or all of ($s*) or (all of ($var*) or all of ($x*) or (1 of ($x*) and 2 of ($var*)) or (all of ($g*) and (2 of ($var*) or 1 of ($x*))))
}
