rule iTranslatorEXE {
    meta:
        author = "ditekSHen"
        description = "Detects iTranslator EXE payload"
        cape_type = "iTranslator Payload"
    strings:
        $s1 = "\\itranslator\\wintrans.exe" fullword wide
        $s2 = "\\SuperX\\SuperX\\Obj\\Release\\SharpX.pdb" fullword ascii
        $s3 = "\\itranslator\\itranslator.dll" fullword ascii
        $s4 = ":Intoskrnl.exe" fullword ascii
        $s5 = "InjectDrv.sys" fullword ascii
        $s6 = "SharpX.dll" fullword wide
        $s7 = "GetMicrosoftEdgeProcessId" ascii
        $s8 = ".php?type=is&ch=" ascii
        $s9 = ".php?uid=" ascii
        $s10 = "&mc=" fullword ascii
        $s11 = "&os=" fullword ascii
        $s12 = "&x=32" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 8 of ($s*)
}

rule iTranslatorDLL {
    meta:
        author = "ditekSHen"
        description = "Detects iTranslator DLL payload"
        cape_type = "iTranslator Payload"
    strings:
        $d1 = "system32\\drivers\\%S.sys" fullword wide
        $d2 = "\\windows\\system32\\winlogon.exe" fullword ascii
        $d3 = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\%s" fullword wide
        $d4 = "\\Registry\\Machine\\SYSTEM\\ControlSet001\\services\\webssx" fullword wide
        $d5 = "\\Device\\CtrlSM" fullword wide
        $d6 = "\\DosDevices\\CtrlSM" fullword wide
        $d7 = "\\driver_wfp\\CbFlt\\Bin\\CbFlt.pdb" ascii
        $d8 = ".php" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
