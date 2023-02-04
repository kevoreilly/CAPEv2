rule DarkComet
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/DarkComet"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        cape_type = "DarkComet Payload"

	strings:
		// Versions 2x
		$a1 = "#BOT#URLUpdate"
		$a2 = "Command successfully executed!"
		$a3 = "MUTEXNAME" wide
		$a4 = "NETDATA" wide
		// Versions 3x & 4x & 5x
		$b1 = "FastMM Borland Edition"
		$b2 = "%s, ClassID: %s"
		$b3 = "I wasn't able to open the hosts file"
		$b4 = "#BOT#VisitUrl"
		$b5 = "#KCMDDC"



	condition:
		all of ($a*) or all of ($b*)
}
