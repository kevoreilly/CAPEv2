rule OzoneRAT {
    meta:
        author = "ditekSHen"
        description = "Detects OzoneRAT / DarkTrack / DarkSky"
        cape_type = "OzoneRAT Payload"
    strings:
        $x1 = "Klog.dat" ascii
        $x2 = "I_AM_DT" ascii
        $x3 = " Alien" ascii
        $x4 = "Local Victim" ascii
        $x5 = "Dtback\\AlienEdition\\Server\\SuperObject.pas" ascii
        $x6 = "].encryptedUsername" ascii
        $x7 = "].encryptedPassword" ascii
        $x8 = { 49 41 4d [6] 44 41 52 [0-2] 4b [6] 44 54 41 43 4b }
        $s1 = "AntiVirusProduct" ascii
        $s2 = "AntiSpywareProduct" ascii
        $s3 = "ConnectServer" ascii
        $s4 = "ExecQuery" ascii
        $s5 = "\\Drivers\\Etc\\Hosts" fullword ascii
        $s6 = "BTMemoryLoadLibary: Get DLLEntyPoint" ascii
        $s7 = "\\\\.\\SyserDbgMsg" fullword ascii
        $s8 = "\\\\.\\SyserBoot" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($x*) or 6 of ($s*))
}
