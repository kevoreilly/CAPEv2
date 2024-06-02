rule Quickbind
{
    meta:
        author = "enzok"
        description = "Quickbind"
        cape_type = "Quickbind Payload"
    strings:
		$anti_appdirs = {E8 [4] 83 F8 0? 7? ?? E8}
		$anti_procs_ram = {E8 [4] 83 F8 0? 7? ?? E8 [4] 3D (FF 0E | 00 0F) 00 00}
		$anti_ram = {E8 [4] 3D (FF 1F | 00 20) 00 00}
		$mutex_1 = {FF [1-5] 3D B7 00 00 00 74 [7-10] 25 89 00 00 00}
		$mutex_2 = {FF 15 [4] 4? 89 C5 4? 85 C0 74 ?? FF 15 [4] 3D B7 00 00 00}
		$mutex_3 = {B9 64 00 00 00 [0-7] FF}
    condition:
        all of ($anti_*) and 2 of ($mutex_*)
}
