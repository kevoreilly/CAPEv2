rule LaZagne
{
meta:
	description = "Identifies LaZagne, credentials recovery project."
	author = "@bartblaze"
	date = "2020-01"
	reference = "https://github.com/AlessandroZ/LaZagne"
	tlp = "White"
	cape_type = "LaZagne Payload"

strings:
	$ = "[!] Specify a directory, not a file !" ascii wide
	$ = "lazagne.config" ascii wide
	$ = "lazagne.softwares" ascii wide
	$ = "blazagne.exe.manifest" ascii wide
	$ = "slaZagne" ascii wide fullword

condition:
	any of them
}
