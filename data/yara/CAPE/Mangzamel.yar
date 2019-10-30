rule Mangzamel
{ 
	meta: 
		cape_type = "Mangzamel Payload"
		description = "This rule will flag on the 4 byte xor loop in later copies of mangzamel with embedded tagging" 
		reference = "Mangzamel Samples" 
		author = "David Cannings" 
		date = "2014-09" 
		filetype = "pe" 

	strings: 
		$xor1 = {8B 1E 83 C0 04 33 D9 83 C6 04 89 58 FC 4A 75 F0} 
		$xor2 = {8B 08 83 C0 04 33 4D 14 89 0A 83 C2 04 4F 75 F0} 
		$xor3 = {53 8B 18 83 C1 04 33 DA 83 C0 04 89 59 FC 4E 75 F0 5B} 

	condition: 
		any of them 
}