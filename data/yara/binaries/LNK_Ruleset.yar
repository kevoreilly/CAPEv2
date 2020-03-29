private rule isLNK
{
meta:
	description = "Private rule identifying shortcut (LNK) files. To be used in conjunction with the other LNK rules below."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$lnk = { 4C 00 00 00 01 14 02 00 }
condition:
	$lnk at 0
}

rule PS_in_LNK
{
meta:
	description = "Identifies PowerShell artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = ".ps1" ascii wide nocase
	$ = "powershell" ascii wide nocase
	$ = "invoke" ascii wide nocase
	$ = "[Convert]" ascii wide nocase
	$ = "FromBase" ascii wide nocase
	$ = "-exec" ascii wide nocase
	$ = "-nop" ascii wide nocase
	$ = "-noni" ascii wide nocase
	$ = "-noninteractive" ascii wide nocase
	$ = "-w hidden" ascii wide nocase
	$ = "-enc" ascii wide nocase
	$ = "-decode" ascii wide nocase
	$ = "bypass" ascii wide nocase
condition:
	isLNK and any of them
}

rule Script_in_LNK
{
meta:
	description = "Identifies scripting artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = "javascript" ascii wide nocase
	$ = "jscript" ascii wide nocase
	$ = "vbscript" ascii wide nocase
	$ = "wscript" ascii wide nocase
	$ = "cscript" ascii wide nocase
	$ = ".js" ascii wide nocase
	$ = ".vb" ascii wide nocase //.vb, .vbs and .vbe
	$ = ".wsc" ascii wide nocase
	$ = ".wsh" ascii wide nocase
	$ = ".wsf" ascii wide nocase
	$ = ".sct" ascii wide nocase
	$ = ".cmd" ascii wide nocase
	$ = ".hta" ascii wide nocase
	$ = ".bat" ascii wide nocase
	$ = "ActiveXObject" ascii wide nocase
	$ = "eval" ascii wide nocase
condition:
	isLNK and any of them
}

rule EXE_in_LNK
{
meta:
	description = "Identifies executable artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = ".exe" ascii wide nocase
	$ = ".dll" ascii wide nocase
	$ = ".scr" ascii wide nocase
	$ = ".pif" ascii wide nocase
	$ = "This program" ascii wide nocase
	$ = "TVqQAA" ascii wide nocase //MZ Base64
condition:
	isLNK and any of them
}

rule Archive_in_LNK
{
meta:
	description = "Identifies archive (compressed) files in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = ".7z" ascii wide nocase
	$ = ".zip" ascii wide nocase
	$ = ".cab" ascii wide nocase
	$ = ".iso" ascii wide nocase
	$ = ".rar" ascii wide nocase
	$ = ".bz2" ascii wide nocase
	$ = ".tar" ascii wide nocase
	$ = ".lzh" ascii wide nocase
	$ = ".dat" ascii wide nocase
	$ = "expand" ascii wide nocase
	$ = "makecab" ascii wide nocase
	$ = "UEsDBA" ascii wide nocase // ZIP Base64
	$ = "TVNDRg" ascii wide nocase //CAB Base64
condition:
	isLNK and any of them
}

rule Execution_in_LNK
{
meta:
	description = "Identifies execution artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = "cmd.exe" ascii wide nocase
	$ = "/c echo" ascii wide nocase
	$ = "/c start" ascii wide nocase
	$ = "/c set" ascii wide nocase
	$ = "%COMSPEC%" ascii wide nocase
	$ = "rundll32.exe" ascii wide nocase
	$ = "regsvr32.exe" ascii wide nocase
	$ = "Assembly.Load" ascii wide nocase
	$ = "[Reflection.Assembly]::Load" ascii wide nocase
	$ = "process call" ascii wide nocase
condition:
	isLNK and any of them
}

rule Compilation_in_LNK
{
meta:
	description = "Identifies compilation artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = "vbc.exe" ascii wide nocase
	$ = "csc.exe" ascii wide nocase
condition:
	isLNK and any of them
}

rule Download_in_LNK
{
meta:
	description = "Identifies download artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = "bitsadmin" ascii wide nocase
	$ = "certutil" ascii wide nocase
	$ = "ServerXMLHTTP" ascii wide nocase
	$ = "http" ascii wide nocase //http and https
	$ = "ftp" ascii wide nocase
	$ = ".url" ascii wide nocase
condition:
	isLNK and any of them
}

rule MSOffice_in_LNK
{
meta:
	description = "Identifies Microsoft Office artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = "winword" ascii wide nocase
	$ = "excel" ascii wide nocase
	$ = "powerpnt" ascii wide nocase
	$ = ".rtf" ascii wide nocase
	$ = ".doc" ascii wide nocase //.doc and .docx
	$ = ".dot" ascii wide nocase //.dot and .dotm
	$ = ".xls" ascii wide nocase //.xls and .xlsx
	$ = ".xla" ascii wide nocase
	$ = ".csv" ascii wide nocase
	$ = ".ppt" ascii wide nocase //.ppt and .pptx
	$ = ".pps" ascii wide nocase //.pps and .ppsx
	$ = ".xml" ascii wide nocase
condition:
	isLNK and any of them
}

rule PDF_in_LNK
{
meta:
	description = "Identifies Adobe Acrobat artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = ".pdf" ascii wide nocase
	$ = "%PDF" ascii wide nocase
condition:
	isLNK and any of them
}

rule Flash_in_LNK
{
meta:
	description = "Identifies Adobe Flash artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = ".swf" ascii wide nocase
	$ = ".fws" ascii wide nocase
condition:
	isLNK and any of them
}

rule SMB_in_LNK
{
meta:
	description = "Identifies SMB (share) artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = "\\c$\\" ascii wide nocase
condition:
	isLNK and any of them
}


rule Long_RelativePath_LNK
{
meta:
	description = "Identifies shortcut (LNK) file with a long relative path. Might be used in an attempt to hide the path."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = "..\\..\\..\\..\\" ascii wide nocase
condition:
	isLNK and any of them
}

rule Large_filesize_LNK
{
meta:
	description = "Identifies shortcut (LNK) file larger than 100KB. Most goodware LNK files are smaller than 100KB."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
condition:
	isLNK and filesize > 100KB
}

import "math"
rule High_Entropy_LNK
{
meta:
	description = "Identifies shortcut (LNK) file with equal or higher entropy than 6.5. Most goodware LNK files have a low entropy, lower than 6."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
condition:
	isLNK and math.entropy(0, filesize) >= 6.5
}

rule CDN_in_LNK
{
meta:
	description = "Identifies CDN (Content Delivery Network) domain in shortcut (LNK) file."
	author = "@bartblaze"
	date = "2020-03"
	tlp = "White"
strings:
	$ = "cdn." ascii wide nocase //May FP
	$ = "githubusercontent" ascii wide nocase
	$ = "googleusercontent" ascii wide nocase
	$ = "cloudfront" ascii wide nocase
	$ = "amazonaws.com" ascii wide nocase
	$ = "akamai" ascii wide nocase
	$ = "cdn77" ascii wide nocase
	$ = "discordapp" ascii wide nocase
condition:
	isLNK and any of them
}
