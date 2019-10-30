rule EternalRomance
{
    meta:
        author = "kevoreilly"
        description = "EternalRomance Exploit"
        cape_type = "EternalRomance Exploit"
    strings:
        $SMB1 = "Frag"
        $SMB2 = "Free"
        $session7_32_1 = {2A 02 1C 00}
        $session7_64_1 = {2A 02 28 00}
        $session8_32_1 = {2A 02 24 00}
        $session8_64_1 = {2A 02 38 00} 
        $session7_32_2 = {D5 FD E3 FF}
        $session7_64_2 = {D5 FD D7 FF}
        $session8_32_2 = {D5 FD DB FF}
        $session8_64_2 = {D5 FD C7 FF} 
        $ipc = "IPC$"
        $pipe1 = "atsvc"
        $pipe2 = "browser"
        $pipe3 = "eventlog"
        $pipe4 = "lsarpc"
        $pipe5 = "netlogon"
        $pipe6 = "ntsvcs"
        $pipe7 = "spoolss"
        $pipe8 = "samr"
        $pipe9 = "srvsvc"
        $pipe10 = "scerpc"
        $pipe11 = "svcctl"
        $pipe12 = "wkssvc"
    condition:
        uint16(0) == 0x5A4D and (all of ($SMB*)) and $ipc and (any of ($session*)) and (any of ($pipe*))
}
