rule Zeppelin
{
meta:
	description = "Identifies Zeppelin ransomware and variants (Buran, Vega etc.)"
	author = "@bartblaze"
	date = "2019-11"
	tlp = "White"
	cape_type = "Zeppelin Payload"

strings:
	$s1 = "TUnlockAndEncryptU" ascii wide
	$s2 = "TDrivesAndShares" ascii wide
	$s3 = "TExcludeFoldersU" ascii wide
	$s4 = "TExcludeFiles" ascii wide
	$s5 = "TTaskKillerU" ascii wide
	$s6 = "TPresenceU" ascii wide
	$s7 = "TSearcherU" ascii wide
	$s8 = "TReadme" ascii wide
	$s9 = "TKeyObj" ascii wide

	$x = "TZeppelinU" ascii wide

condition:
	2 of ($s*) or $x
}
