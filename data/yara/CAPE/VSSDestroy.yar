rule VSSDestroy {
    meta:
        author = "ditekshen"
        description = "VSSDestroy/Matrix ransomware payload"
        cape_type = "VSSDestroy payload"
    strings:
        $o1 = "[SHARESSCAN]" wide
        $o2 = "[LDRIVESSCAN]" wide
        $o3 = "[LOGSAVED]" wide
        $o4 = "[LPROGRESS]" wide
        $o5 = "[FINISHSAVED]" wide
        $o6 = "[ALL_LOCAL_KID]" wide
        $o7 = "[DIRSCAN" wide
        $o8 = "[GENKEY]" wide
        $s1 = "\\cmd.exe" nocase wide
        $s2 = "/C powershell \"" nocase wide
        $s3 = "%COMPUTERNAME%" wide
        $s4 = "%USERNAME%" wide
        $s5 = "Error loading Socket interface (ws2_32.dll)!" wide
        $s6 = "Old file list dump found. Want to load it? (y/n):" fullword wide
    condition:
        (uint16(0) == 0x5a4d and 4 of ($o*) and 3 of ($s*)) or (5 of ($o*) and 4 of ($s*))
}
