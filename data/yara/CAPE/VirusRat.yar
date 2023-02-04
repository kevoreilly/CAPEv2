rule VirusRat
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/VirusRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        cape_type = "VirusRat Payload"

	strings:
		$string0 = "virustotal"
		$string1 = "virusscan"
		$string2 = "abccba"
		$string3 = "pronoip"
		$string4 = "streamWebcam"
		$string5 = "DOMAIN_PASSWORD"
		$string6 = "Stub.Form1.resources"
		$string7 = "ftp://{0}@{1}" wide
		$string8 = "SELECT * FROM moz_logins" wide
		$string9 = "SELECT * FROM moz_disabledHosts" wide
		$string10 = "DynDNS\\Updater\\config.dyndns" wide
		$string11 = "|BawaneH|" wide

	condition:
		all of them
}
