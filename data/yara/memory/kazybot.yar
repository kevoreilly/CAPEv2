// Copyright (C) 2015 KillerInstinct
// The contents of this file are Yara rules processed by procmemory.py processing
// module. Add your signatures here.
rule KazyBot_RAT
{
    meta:
        author = "KillerInstinct"
        description = "Strings indicitive of unpacked KazyBot RAT"
		malfamily = "kazybot"

    strings:
        $pdb1 = /[A-Za-z]:\\[^\\]+\\KazyBot\\PluginServer\\[^\.]+.pdb/
        $pdb2 = /[A-Za-z]:\\[^\\]+\\KazyBot\\SharedCode\\[^\.]+.pdb/
        $cmd1 = "MonitorOn" fullword ascii
        $cmd2 = "MonitorOff" fullword ascii
        $cmd3 = "StartLiveKeylogger" fullword ascii
        $cmd4 = "StopLiveKeylogger" fullword ascii
        $cmd5 = "LiveKeyLog" fullword ascii
        $cmd6 = "GetKeyLog" fullword ascii
        $cmd7 = "GetPasswords" fullword ascii
        $cmd8 = "StartStress" fullword ascii
        $cmd9 = "StopStress" fullword ascii
        $cmd10 = "ChromeStealer" fullword ascii

    condition:
        any of ($pdb*) or 8 of ($cmd*)
}
