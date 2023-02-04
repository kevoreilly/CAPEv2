import "pe"

rule KdcSponge {
    meta:
        author = "ditekSHen"
        description = "Detects KdcSponge"
        cape_type = "KdcSponge Payload"
    strings:
        $x1 = "\\share\\kdcdll\\user641.pdb" ascii
        $x2 = "5ADSelf@tech*7890" fullword wide
        $kdc1 = "KdcVerifyEncryptedTimeStamp" ascii wide nocase
        $kdc2 = "KerbHashPasswordEx3" ascii wide nocase
        $kdc3 = "KerbFreeKey" ascii wide nocase
        $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $r2 = "KDC Service" fullword ascii
        $s1 = "download//symbols//%S//%S//%S" fullword wide
        $s2 = "c:\\windows\\system32\\kdcsvc.dll" fullword wide nocase
        $s3 = /WinHttp(Send|Receive)(Request|Response) failed (0x%.8X)/ fullword wide
    condition:
        uint16(0) == 0x5a4d and (
            (1 of ($x*) and 2 of them) or (all of ($kdc*) and (1 of ($x*) or all of ($r*) or 2 of ($s*))) or (8 of them) or
            (
                pe.exports("MainFun") and
                pe.exports("NetApiBufferFree") and
                pe.exports("BeaEngineRevision") and
                pe.exports("BeaEngineVersion") and
                pe.exports("Disasm") and
                pe.exports("DllRegisterServer") and
                pe.exports("DsGetDcName") and
                2 of them
            )
        )
}
