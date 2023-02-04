rule BreakWin {
    meta:
        author = "ditekSHen"
        description = "Detects BreakWin Wiper"
        cape_type = "BreakWin Wiper Payload"
    strings:
        $s1 = "Started wiping file %s with %s." fullword wide
        $s2 = "C:\\Program Files\\Lock My PC" wide
        $s3 = "Stardust is still alive." fullword wide
        $s4 = "Failed to terminate the locker process." fullword wide
        $s5 = "C:\\Windows\\System32\\cmd.exe" fullword wide
        $s6 = "Process created successfully. Executed command: %s." fullword wide
        $s7 = "locker_background_image_path" fullword ascii
        $s8 = "takeown.exe /F \"C:\\Windows\\Web\\Screen\" /R /A /D Y" fullword ascii
        $s9 = "icacls.exe \"C:\\Windows\\Web\\Screen\" /reset /T" fullword ascii
        $s10 = "takeown.exe /F \"C:\\ProgramData\\Microsoft\\Windows\\SystemData\" /R /A /D Y" fullword ascii
        $s11 = ".?AVProcessSnapshotCreationFailedException@@" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
