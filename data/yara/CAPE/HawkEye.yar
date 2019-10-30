rule HawkEye
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/HawkEye"
		maltype = "KeyLogger"
		filetype = "exe"
        cape_type = "HawkEye Payload"

	strings:
		$key = "HawkEyeKeylogger" wide
		$salt = "099u787978786" wide
		$string1 = "HawkEye_Keylogger" wide
		$string2 = "holdermail.txt" wide
		$string3 = "wallet.dat" wide
		$string4 = "Keylog Records" wide
        $string5 = "<!-- do not script -->" wide
        $string6 = "\\pidloc.txt" wide
        $string7 = "BSPLIT" wide
        

	condition:
		$key and $salt and all of ($string*)
}