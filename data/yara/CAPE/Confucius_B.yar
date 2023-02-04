rule Confucius_B
{
meta:
	description = "Identifies Confucius malware."
	author = "@bartblaze"
	date = "2020-04"
	reference = "https://unit42.paloaltonetworks.com/unit42-confucius-says-malware-families-get-further-by-abusing-legitimate-websites/"
	tlp = "White"
	cape_type = "Confucius_B Payload"

strings:
	$ = "----BONE-79A8DE0E314C50503FF2378aEB126363-" ascii wide
	$ = "----MUETA-%.08x%.04x%.04x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x-" ascii wide
	$ = "C:\\Users\\DMITRY-PC\\Documents\\JKE-Agent-Win32\\JKE_Agent_DataCollectorPlugin\\output\\Debug\\JKE_Agent_DumbTestPlugin.dll" ascii wide

condition:
	any of them
}
