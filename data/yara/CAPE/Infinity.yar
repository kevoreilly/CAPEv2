rule Infinity
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/Infinity"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        cape_type = "Infinity Payload"

	strings:
		$a = "CRYPTPROTECT_PROMPTSTRUCT"
		$b = "discomouse"
		$c = "GetDeepInfo"
		$d = "AES_Encrypt"
		$e = "StartUDPFlood"
		$f = "BATScripting" wide
		$g = "FBqINhRdpgnqATxJ.html" wide
		$i = "magic_key" wide

	condition:
		all of them
}
