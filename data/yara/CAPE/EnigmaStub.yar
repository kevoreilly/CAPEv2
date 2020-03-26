rule EnigmaStub
{
meta:
	description = "Identifies Enigma packer stub."
	author = "@bartblaze"
	date = "2020-03"
	tlp = "White"
	cape_type = "Enigma Stub"

strings:	
	$ = "Enigma anti-emulators plugin - GetProcAddress" ascii wide
	$ = "Enigma anti-debugger plugin - CheckRemoteDebuggerPresent" ascii wide
	$ = "Enigma anti-debugger plugin - IsDebuggerPresent" ascii wide
	$ = "Enigma Sandboxie Detect plugin" ascii wide
	$ = "Enigma_Plugin_Description" ascii wide
	$ = "Enigma_Plugin_About" ascii wide
	$ = "Enigma_Plugin_OnFinal" ascii wide
	$ = "EnigmaProtector" ascii wide
	$ = "Enigma_Plugin_OnInit" ascii wide

condition:
	any of them
}