rule CrimsonRAT {
    meta:
        author = "ditekSHen"
        description = "Detects CrimsonRAT"
        cape_type = "CrimsonRAT Payload"
    strings:
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|" fullword wide
        $s2 = "system volume information|" fullword wide
        $s3 = "program files (x86)|" fullword wide
        $s4 = "program files|" fullword wide
        $s5 = "<SAVE_AUTO<|" fullword wide
        $s6 = "add_up_files" fullword ascii
        $s7 = "see_folders" ascii
        $s8 = "see_files" ascii
        $s9 = "see_scren" ascii
        $s10 = "see_recording" ascii
        $s11 = "see_responce" ascii
        $s12 = "pull_data" ascii
        $s13 = "do_process" ascii
        $s14 = "do_updated" ascii
        $s15 = "IPSConfig" fullword ascii
        $s16 = "#Runing|ver#" wide
        $s17 = "|fileslog=" wide
    condition:
        uint16(0) == 0x5a4d and 6 of them
}
