rule OLEfile_in_CAD_FAS_LSP
{
meta:
	description = "Identifies OLE files embedded in AutoCAD and related Autodesk files, quite uncommon and potentially malicious."
	author = "@bartblaze"
	date = "2019-12"
	reference = "https://blog.didierstevens.com/2019/12/16/analyzing-dwg-files-with-vba-macros/"
	tlp = "White"

strings:
	$acad = {41 43 31} //AC1 (old format follows with 0x2E, new with 0x30)
	$fas = {0D 0A 20 46 41 53 34 2D 46 49 4C 45 20 3B 20 44 6F 20 6E 6F 74 20 63 68 61 6E 67 65 20 69 74 21}
	$lsp1 = "acaddoc.lsp"
	$lsp2 = "doc.lsp"
	$lsp3 = "doclsp"
	$lsp4 = "lspfilelist"
	$ole = {D0 CF 11 E0}

condition:
	($acad at 0 and $ole) or
	($fas at 0 and $ole) or
	((any of ($lsp*)) and $ole)
}
