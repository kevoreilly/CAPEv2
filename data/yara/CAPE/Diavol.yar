rule Diavol {
    meta:
        author = "ditekSHen"
        description = "Detects Diavol ransomware"
        cape_type = "Diavol Payload"
    strings:
        $s1 = "README_FOR_DECRYPT.txt" ascii wide nocase
        $s2 = ".lock64" fullword ascii wide
        $s3 = "LockMainDIB" ascii wide
        $s4 = "locker.divided" ascii wide
        $s5 = "%tob_dic%/" wide
        $s6 = "%cid_bot%" wide
        $m1 = "GENBOTID" ascii wide
        $m2 = "SHAPELISTS" ascii wide
        $m3 = "REGISTER" ascii wide
        $m4 = "FROMNET" ascii wide
        $m5 = "SERVPROC" ascii wide
        $m6 = "SMBFAST" ascii wide
        $c1 = "/Bnyar8RsK04ug/" fullword ascii
        $c2 = "/landing" fullword ascii
        $c3 = "/wipe" fullword ascii
        $c4 = "&ip_local1=111.111.111.111&ip_local2=222.222.222.222&ip_external=2.16.7.12" fullword ascii
        $c5 = "&group=" fullword ascii
        $c6 = "/BnpOnspQwtjCA/register" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or 5 of ($m*) or 4 of ($c*) or 7 of them)
}
