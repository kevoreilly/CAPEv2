rule EpicenterRAT {
    meta:
        author = "ditekSHen"
        description = "Detects EpicenterRAT"
        cape_type = "EpicenterRAT Payload"
    strings:
        $pdb1 = "c:\\Users\\Zombie\\Desktop\\MutantNinja\\" ascii
        $pdb2 = "\\Epicenter Client\\" ascii
        $s1 = "PROCESS_LIST<%SEP%>" fullword wide
        $s2 = "GETREADY_RECV_FILE<%SEP%>" fullword wide
        $s3 = "DISPLAY<%SEP%>" wide
        $s4 = "GETSCREEN<%SEP%>" fullword wide
        $s5 = "dumpImageName" fullword ascii
        $s6 = "dumpLoc" fullword ascii
        $s7 = "EXPECT<%SEP%>filelist<%SEP%>" fullword wide
        $s8 = "<%FSEP%>FOLDER<%FSEP%>-<%SEP%>" fullword wide
        $s9 = "KILLPROC<%SEP%>" fullword wide
        $s10 = "LAUNCHPROC<%SEP%>" fullword wide
        $s11 = "cmd.exe /c start /b " fullword wide
        $s12 = "savservice" fullword wide
        $s13 = "getvrs" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($pdb*) or 5 of ($s*))
}
