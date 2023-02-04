rule LuxNet
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/LuxNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        cape_type = "LuxNet Payload"

	strings:
		$a = "GetHashCode"
		$b = "Activator"
		$c = "WebClient"
		$d = "op_Equality"
		$e = "dickcursor.cur" wide
		$f = "{0}|{1}|{2}" wide

	condition:
		all of them
}
