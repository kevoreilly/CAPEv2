import "pe"
rule HiddenVNC
{
meta:
	description = "Identifies HiddenVNC, which can start remote sessions."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
	cape_type = "HiddenVNC Payload"

strings:
	$ = "#hvnc" ascii wide
	$ = "VNC is starting your browser..." ascii wide
	$ = "HvncAction" ascii wide
	$ = "HvncCommunication" ascii wide
	$ = "hvncDesktop" ascii wide

condition:
	2 of them or
	(pe.exports("VncStartServer") and
	pe.exports("VncStopServer"))
}
