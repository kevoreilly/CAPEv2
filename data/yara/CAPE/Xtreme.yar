rule Xtreme
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/Xtreme"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		ver = "2.9, 3.1, 3.2, 3.5"
        cape_type = "Xtreme Payload"

	strings:
		$a = "XTREME" wide
		$b = "ServerStarted" wide
		$c = "XtremeKeylogger" wide
		$d = "x.html" wide
		$e = "Xtreme RAT" wide

	condition:
		all of them
}
