rule UPX
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"

	strings:
		$a = "UPX0"
		$b = "UPX1"
		$c = "UPX!"

	condition:
		all of them
}