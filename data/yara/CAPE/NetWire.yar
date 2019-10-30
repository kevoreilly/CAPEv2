rule NetWire
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net> & David Cannings"
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

    condition:
        all of them
}
