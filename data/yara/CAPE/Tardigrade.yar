import "pe"

rule Tardigrade {
    meta:
        author = "ditekSHen"
        description = "Detects Tardigrade"
        cape_type = "Tardigrade Payload"
    strings:
        $x1 = "cmd.exe /c echo kOJAdtQoDcMuogIZIl>\"%s\"&exit" fullword ascii
        $x2 = "cmd.exe /c echo HBnBcZPeUevCDQmKGzXxYJHqpzRAbRCQCihOxiLi>\"%s\"&exit" fullword ascii
        $x3 = "cmd.exe /c set kpUUCjoLWLZvJFc=3167 & reg add HKCU\\SOFTWARE\\EQwIobTRgsJ /v PDMXPmqSYnUx /t REG_DWORD /d 10080 & exit" fullword ascii
        //$x4 = "DEMOBLABLA" fullword ascii
        $s1 = "ReplaceFileA" ascii
        $s2 = "FlushFileBuffers" ascii
        $s3 = "WaitNamedPipeA" ascii
        $s4 = "ImpersonateNamedPipeClient" ascii
        $s5 = "RegFlushKey" ascii
        $s6 = /cmd\.exe \/c (echo|set)/ ascii
        $s7 = ">\"%s\"&exit" ascii
    condition:
        uint16(0) == 0x5a4d and pe.is_dll() and (1 of ($x*) or 6 of ($s*)) and
        (
            pe.exports("DllGetClassObject") and
            pe.exports("DllMain") and
            pe.exports("DllRegisterServer") and
            pe.exports("DllUnregisterServer") and
            pe.exports("InitHelperDll") and
            pe.exports("StartW")
        )
}
