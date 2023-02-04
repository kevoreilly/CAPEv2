rule Sfile
{
meta:
	description = "Identifies Sfile aka Escal ransomware."
	author = "@bartblaze"
	date = "2020-09"
	tlp = "White"
	cape_type = "Sfile Payload"

strings:
	$pdb = "D:\\code\\ransomware_win\\bin\\ransomware.pdb" ascii wide

	$ = "%s SORTING time : %s" ascii wide
	$ = "%ws -> WorkModeDecryptFiles : %d of %d files decrypted +%d (%d MB)..." ascii wide
	$ = "%ws -> WorkModeEncryptFiles : %d of %d files encrypted +%d [bps : %d, size = %d MB] (%d skipped, ld = %d.%d.%d %d:%d:%d, lf = %ws)..." ascii wide
	$ = "%ws -> WorkModeEnded" ascii wide
	$ = "%ws -> WorkModeFindFiles : %d files / %d folders found (already (de?)crypted %d/%d) (lf = %ws)..." ascii wide
	$ = "%ws -> WorkModeSorting" ascii wide
	$ = "%ws ENCRYPTFILES count : %d (%d skipped), time : %s" ascii wide
	$ = "%ws FINDFILES RESULTS : dwDirectoriesCount = %d, dwFilesCount = %d MB = %d (FIND END)" ascii wide
	$ = "%ws FINDFILES time : %s" ascii wide
	$ = "DRIVE_FIXED : %ws" ascii wide
	$ = "EncryptDisk(%ws) DONE" ascii wide
	$ = "ScheduleRoutine() : gogogo" ascii wide
	$ = "ScheduleRoutine() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
	$ = "WARN! FileLength more then memory has %ws" ascii wide
	$ = "WaitForHours() : gogogo" ascii wide
	$ = "WaitForHours() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
	$ = "Your network has been penetrated." ascii wide
	$ = "--kill-susp" ascii wide
	$ = "--enable-shares" ascii wide

condition:
	$pdb or 3 of them
}
