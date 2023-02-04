rule Responder
{
meta:
	description = "Identifies Responder, an LLMNR, NBT-NS and MDNS poisoner."
	author = "@bartblaze"
	date = "2020-08"
	reference = "https://github.com/lgandx/Responder"
	tlp = "White"
	cape_type = "Responder Payload"

strings:
	//Only when ran on the host itself
	$ = "[*] [LLMNR]" ascii wide
	$ = "[*] [NBT-NS]" ascii wide
	$ = "[*] [MDNS]" ascii wide
	$ = "[FINGER] OS Version" ascii wide
	$ = "[FINGER] Client Version" ascii wide
	$ = "serve_thread_udp_broadcast" ascii wide
	$ = "serve_thread_tcp_auth" ascii wide
	$ = "serve_NBTNS_poisoner" ascii wide
	$ = "serve_MDNS_poisoner" ascii wide
	$ = "serve_LLMNR_poisoner" ascii wide
	$ = "poisoners.LLMNR " ascii wide
	$ = "poisoners.NBTNS" ascii wide
	$ = "poisoners.MDNS" ascii wide

condition:
	any of them
}
