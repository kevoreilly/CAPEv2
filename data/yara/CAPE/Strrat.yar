rule Strrat
{
	meta:
		author = "enzo"
		description = "Strrat Rat"
		cape_type = "Strrat Payload"
	strings:
		$string1 = "config.txt" ascii
		$string2 = "carLambo" ascii
		$string3 = "META-INF" ascii
	condition:
		all of them
}
