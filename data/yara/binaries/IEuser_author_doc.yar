rule IEuser_author_doc
{
meta:
	description = "Identifies Microsoft Word documents created with the default user on IE11 test VMs."
	author = "@bartblaze"
	date = "2020-12"
	reference = "https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/"
	tlp = "White"

strings:
	$doc = {D0 CF 11 E0}
	$ieuser = {49 00 45 00 55 00 73 00 65 00 72} //i.e.u.s.e.r

condition:
	$doc at 0 and $ieuser
}
