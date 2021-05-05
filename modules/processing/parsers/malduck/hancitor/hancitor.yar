rule hancitor {
	meta:
		author      = "Myrtus0x0"
		description = "URL arguments for Hancitor unpacked samples"
		created     = "2021-05-01"
		type        = "malware.stealer/malware.downloader"
		os          = "windows"
		tlp         = "white"
		rev         = 1
	strings:
		$url_args_64 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)" ascii wide fullword
		$url_args_32 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)" ascii wide fullword
	condition:
		uint16(0) == 0x5A4D and
		all of them
}
