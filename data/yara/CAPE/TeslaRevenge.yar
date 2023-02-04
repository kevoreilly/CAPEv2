rule TeslaRevenge {
    meta:
        author = "ditekSHen"
        description = "Detects TeslaRevenge ransomware"
        cape_type = "TeslaRevenge Payload"
    strings:
        $s1 = "autospreadifnoav=" ascii wide
        $s2 = "autospread=" ascii wide
        $s3 = "noencryptext=" ascii wide
        $s4 = "teslarvng" wide
        $s5 = "finished encrypting" wide nocase
        $s6 = "net scan" wide nocase
        $s7 = "for /f %%x in ('wevtutil el') do wevtutil cl" ascii
        $s8 = "tasklist | find /i \"SDELETE.exe\"" ascii
        $e1 = "mshta.exe" ascii wide nocase
        $e2 = "sc.exe" ascii wide nocase
        $e3 = "vssadmin.exe" ascii wide nocase
        $e4 = "wbadmin.exe" ascii wide nocase
        $e5 = "cmd.exe" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or (all of ($e*) and 2 of ($s*)))
}
