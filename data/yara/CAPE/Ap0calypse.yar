rule Ap0calypse
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/Ap0calypse"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        cape_type = "Ap0calypse Payload"

	strings:
		$a = "Ap0calypse"
		$b = "Sifre"
		$c = "MsgGoster"
		$d = "Baslik"
		$e = "Dosyalars"
		$f = "Injecsiyon"

	condition:
		all of them
}
