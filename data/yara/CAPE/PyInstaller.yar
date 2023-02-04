import "pe"
import "hash"
rule PyInstaller
{
meta:
	description = "Identifies executable converted using PyInstaller."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"

strings:
	$ = "pyi-windows-manifest-filename" ascii wide
	$ = "pyi-runtime-tmpdir" ascii wide
	$ = "PyInstaller: " ascii wide

condition:
	uint16(0) == 0x5a4d and any of them or
	(
   for any i in (0..pe.number_of_resources - 1):
     (pe.resources[i].type == pe.RESOURCE_TYPE_ICON and
      hash.md5(pe.resources[i].offset, pe.resources[i].length) ==
      "20d36c0a435caad0ae75d3e5f474650c") //Default PyInstaller icon
	)
}
