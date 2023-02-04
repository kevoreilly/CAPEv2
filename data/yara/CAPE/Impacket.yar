rule Impacket
{
meta:
	description = "Identifies Impacket, a collection of Python classes for working with network protocols."
	author = "@bartblaze"
	date = "2020-08"
	reference = "https://github.com/SecureAuthCorp/impacket"
	tlp = "White"

strings:
	$ = "impacket.crypto" ascii wide
	$ = "impacket.dcerpc" ascii wide
	$ = "impacket.examples" ascii wide
	$ = "impacket.hresult_errors" ascii wide
	$ = "impacket.krb5" ascii wide
	$ = "impacket.nmb" ascii wide
	$ = "impacket.nt_errors" ascii wide
	$ = "impacket.ntlm" ascii wide
	$ = "impacket.smb" ascii wide
	$ = "impacket.smb3" ascii wide
	$ = "impacket.smb3structs" ascii wide
	$ = "impacket.smbconnection" ascii wide
	$ = "impacket.spnego" ascii wide
	$ = "impacket.structure" ascii wide
	$ = "impacket.system_errors" ascii wide
	$ = "impacket.uuid" ascii wide
	$ = "impacket.version" ascii wide
	$ = "impacket.winregistry" ascii wide

condition:
	any of them
}
