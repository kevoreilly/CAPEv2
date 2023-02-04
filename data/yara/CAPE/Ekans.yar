rule Ekans
{
meta:
	description = "Identifies Ekans aka Snake ransomware unpacked or in memory."
	author = "@bartblaze"
	date = "2020-03"
	tlp = "White"
	cape_type = "Snake Payload"

strings:
	$ = "already encrypted!" ascii wide
	$ = "cant kill process %v : %v" ascii wide
	$ = "could not access service: %v" ascii wide
	$ = "could not retrieve service status: %v" ascii wide
	$ = "could not send control=%d: %v" ascii wide
	$ = "error encrypting %v : %v" ascii wide
	$ = "faild to get process list" ascii wide
	$ = "priority files: %v" ascii wide
	$ = "priorityFiles: %v" ascii wide
	$ = "pub: %v" ascii wide
	$ = "root: %v" ascii wide
	$ = "There can be only one" ascii wide
	$ = "timeout waiting for service to go to state=%d" ascii wide
	$ = "Toatal files: %v" ascii wide
	$ = "total lengt: %v" ascii wide
	$ = "worker %s started job %s" ascii wide

condition:
	3 of them
}
