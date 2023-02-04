rule Chuwi {
    meta:
        author = "ditekSHen"
        description = "Detects detected unknown RAT. Called Chuwi based on PDB"
        cape_type = "Chuwi RAT Payload"
    strings:
        $cmd1 = "shell_command" fullword ascii
        $cmd2 = "check_command" fullword ascii
        $cmd3 = "down_exec" fullword ascii
        $cmd4 = "open_link" fullword ascii
        $cmd5 = "down_exec" fullword ascii
        $cmd6 = "exe_link" fullword ascii
        $cmd7 = "shellCommand" fullword ascii
        $cmd8 = "R_CMMAND" fullword ascii

        $cnc1 = "/check_command.php?HWID=" ascii
        $cnc2 = "&act=get_command" ascii
        $cnc3 = "/get_command.php?hwid=" ascii
        $cnc4 = "&command=down_exec" ascii
        $cnc5 = "&command=message" ascii
        $cnc6 = "&command=open_link" ascii
        $cnc7 = "&command=down_exec" ascii
        $cnc8 = "&command=shell" ascii

        $pdb = "\\Users\\CHUWI\\Documents\\CPROJ\\Downloader\\svchost" ascii
    condition:
        uint16(0) == 0x5a4d and ($pdb or 5 of ($cmd*) or 4 of ($cnc*) or 8 of them)
}
