rule QuilClipper {
    meta:
        author = "ditekSHen"
        description = "Detects QuilClipper variants mostly in memory or extracted AutoIt script"
        cape_type = "QuilClipper Payload"
    strings:
        $cnc1 = "QUILCLIPPER by" ascii
        $cnc2 = "/ UserName:" ascii
        $cnc3 = "/ System:" ascii
        $s1 = "DLLCALL ( \"kernel32.dll\" , \"handle\" , \"CreateMutexW\" , \"struct*\"" ascii
        $s2 = "SHELLEXECUTE ( @SCRIPTFULLPATH , \"\" , \"\" , FUNC_" ascii
        $s3 = "CASE BITROTATE" ascii
        $s4 = "CASE BITXOR" ascii
        $s5 = "CLIP( FUNC_" ascii
        $s6 = "CLIPPUT (" ascii
        $s7 = "FUNC _CLIPPUTFILE(" ascii
        $s8 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Schedule" ascii
    condition:
        all of ($cnc*) or all of ($s*)
}
