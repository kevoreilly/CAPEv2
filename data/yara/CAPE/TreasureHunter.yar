rule TreasureHunter {
	meta:
		description = "Detects generic unpacked TreasureHunter POS"
		author = "@VK_Intel"
		reference = "TreasureHunter POS"
		date = "2018-07-08"
		hash = "f4ba09a65d5e0a72677580646c670d739c323c3bca9f4ff29aa88f58057557ba"
        cape_type = "TreasureHunter Payload"
	strings:

		$magic = { 4d 5a }

		$s0 = "Error - Treasure Hunter is already running on this computer! To re-install, close the jucheck.exe process and try again" fullword wide
		$s1 = "C:\\Users\\user\\Desktop\\trhutt34C\\cSources\\treasureHunter\\Release\\treasureHunter.pdb" fullword ascii
		$s2 = "Couldn't get a snapshot of the memory processes!" fullword wide
		$s3 = "TreasureHunter version 0.1 Alpha, created by Jolly Roger (jollyroger@prv.name) for BearsInc. Greets to Xylitol and co." fullword wide
		$s4 = "Couldn't get debug privileges" fullword wide
		$s5 = "Failed to execute the file" fullword wide
		$s6 = "ssuccessfully sent the dumps!" fullword wide
		$s7 = "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; ." ascii
		$s8 = "Successfully executed the file" fullword wide
		$s9 = "Cannot find %AppData%!" fullword wide
		$s10 = "\\Windows\\explorer.exe" fullword ascii
		$s11 = "\\jucheck.exe" fullword ascii

	condition:
		$magic at 0 and filesize < 235KB and 9 of ($s*)
}