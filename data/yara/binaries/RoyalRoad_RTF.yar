rule RoyalRoad_RTF
{
meta:
	description = "Identifies RoyalRoad RTF, used by multiple Chinese APT groups."
	author = "@bartblaze"
	date = "2020-01"
	reference = "https://nao-sec.org/2020/01/an-overhead-view-of-the-royal-road.html"
	tlp = "White"

strings:
	$rtf = "{\\rt"

	//\tmp\8.t
	$RR1 = "5C746D705C382E74" ascii wide nocase
	//\AppData\Local\Temp\8.t
	$RR2 = "5C417070446174615C4C6F63616C5C54656D705C382E74" ascii wide nocase

condition:
	$rtf at 0 and any of ($RR*)
}
