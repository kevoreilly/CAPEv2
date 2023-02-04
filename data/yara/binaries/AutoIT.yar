rule AutoIT_Compiled
{
meta:
	description = "Identifies compiled AutoIT script (as EXE)."
	author = "@bartblaze"
	date = "2020-09"
	tlp = "White"

strings:
	$ = "#OnAutoItStartRegister" ascii wide
	$ = "#pragma compile" ascii wide
	$ = "/AutoIt3ExecuteLine" ascii wide
	$ = "/AutoIt3ExecuteScript" ascii wide
	$ = "/AutoIt3OutputDebug" ascii wide
	$ = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
	$ = ">>>AUTOIT SCRIPT<<<" ascii wide
	$ = "This is a third-party compiled AutoIt script." ascii wide

condition:
	uint16(0) == 0x5A4D and any of them
}

rule AutoIT_Script
{
meta:
	description = "Identifies AutoIT script."
	author = "@bartblaze"
	date = "2020-09"
	tlp = "White"

strings:
	$ = "#OnAutoItStartRegister" ascii wide
	$ = "#pragma compile" ascii wide
	$ = "/AutoIt3ExecuteLine" ascii wide
	$ = "/AutoIt3ExecuteScript" ascii wide
	$ = "/AutoIt3OutputDebug" ascii wide
	$ = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
	$ = ">>>AUTOIT SCRIPT<<<" ascii wide
	$ = "This is a third-party compiled AutoIt script." ascii wide

condition:
	uint16(0) != 0x5A4D and any of them
}
