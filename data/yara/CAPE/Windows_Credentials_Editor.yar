rule Windows_Credentials_Editor
{
meta:
	description = "Identifies Windows Credentials Editor (WCE), post-exploitation tool."
	author = "@bartblaze"
	date = "2020-01"
	reference = "https://www.ampliasecurity.com/research/windows-credentials-editor/"
	tlp = "White"
	cape_type = "WCE Payload"

strings:
	$ = "Windows Credentials Editor" ascii wide
	$ = "Can't enumerate logon sessions!" ascii wide
	$ = "Cannot get PID of LSASS.EXE!" ascii wide
	$ = "Error: cannot dump TGT" ascii wide
	$ = "Error: Cannot extract auxiliary DLL!" ascii wide
	$ = "Error: cannot generate LM Hash." ascii wide
	$ = "Error: cannot generate NT Hash." ascii wide
	$ = "Error: Cannot open LSASS.EXE!." ascii wide
	$ = "Error in cmdline!." ascii wide
	$ = "Forced Safe Mode Error: cannot read credentials using 'safe mode'." ascii wide
	$ = "Reading by injecting code! (less-safe mode)" ascii wide
	$ = "username is too long!." ascii wide
	$ = "Using WCE Windows Service.." ascii wide
	$ = "Using WCE Windows Service..." ascii wide
	$ = "Warning: I will not be able to extract the TGT session key" ascii wide
	$ = "WCEAddNTLMCredentials" ascii wide
	$ = "wceaux.dll" ascii wide fullword
	$ = "WCEGetNTLMCredentials" ascii wide
	$ = "wce_ccache" ascii wide fullword
	$ = "wce_krbtkts" ascii wide fullword

condition:
	3 of them
}
