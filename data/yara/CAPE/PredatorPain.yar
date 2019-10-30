rule PredatorPain
{

	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/PredatorPain"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        cape_type = "PredatorPain Payload"

	strings:
		$string1 = "holderwb.txt" wide
		$string3 = "There is a file attached to this email" wide
		$string4 = "screens\\screenshot" wide
		$string5 = "Disablelogger" wide
		$string6 = "\\pidloc.txt" wide
        $string7 = "clearie" wide
        $string8 = "clearff" wide
        $string9 = "emails should be sent to you shortly" wide
        $string10 = "jagex_cache\\regPin" wide
        $string11 = "open=Sys.exe" wide
		$ver1 = "PredatorLogger" wide
		$ver2 = "EncryptedCredentials" wide
        $ver3 = "Predator Pain" wide

	condition:
		7 of ($string*) and any of ($ver*)
}