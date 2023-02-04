rule Jupyter
{
meta:
	description = "Identifies Jupyter aka SolarMarker, backdoor."
	author = "@bartblaze"
	date = "2021-06"
	tlp = "White"
	cape_type = "Jupyter Payload"

strings:
	$ = "var __addr__=" ascii wide
	$ = "var __hwid__=" ascii wide
	$ = "var __xkey__=" ascii wide
	$ = "solarmarker.dat" ascii wide

condition:
	3 of them
}
