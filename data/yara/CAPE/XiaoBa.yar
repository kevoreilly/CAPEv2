rule XiaoBa
{
meta:
	description = "Identifies XiaoBa ransomware unpacked or in memory."
	author = "@bartblaze"
	date = "2019-09"
	tlp = "White"
	cape_type = "XiaoBa Payload"

strings:
	$ = "BY:TIANGE" ascii wide
	$ = "Your disk have a lock" ascii wide
	$ = "Please enter the unlock password" ascii wide
	$ = "Please input the unlock password" ascii wide
	$ = "I am very sorry that all your files have been encrypted" ascii wide

condition:
	any of them
}
