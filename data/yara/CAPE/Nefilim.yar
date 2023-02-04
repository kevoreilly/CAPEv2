rule Nefilim {
    meta:
        author = "ditekSHen"
        description = "Detects Nemty/Nefilim ransomware"
        cape_type = "Nefilim Payload"
    strings:
        $s1 = "Go build ID:" ascii
        $s2 = "GOMAXPROCSGetIfEntryGetVersionGlagoliticKharoshthiManichaeanOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCODEPhoenicianSaurasht" ascii
        $s3 = "crypto/x509.ExtKeyUsage" ascii
        $s4 = "crypto/x509.KeyUsageContentCommitment" ascii
        $s5 = "DEK-Info header" ascii
        $s6 = "GetUserProfileDirectoryWMagallanes Standard TimeMontevideo Standard TimeNorth Asia Standard TimePacific SA Standard TimeQueryPerformanceCounter" fullword ascii
        $s7 = "*( -  <  =  >  k= m=%: +00+03+04+05+06+07+08+09+10+11+12+13+14-01-02-03-04-05-06-08-09-11-12..." ascii
        $s8 = "Go cmd/compile go1.10" fullword ascii
        $s9 = ".dllprogramdatarecycle.bin" ascii
        $s10 = ".dll.exe.lnk.sys.url" ascii
        $vx1_1 = "Fa1led to os.OpenFile()" ascii
        $vx1_2 = "-HELP.txt" ascii
        $vf1_1 = "main.CTREncrypt" fullword ascii
        $vf1_2 = "main.FileSearch" fullword ascii
        $vf1_3 = "main.getdrives" fullword ascii
        $vf1_4 = "main.RSAEncrypt" fullword ascii
        $vf1_5 = "main.SaveNote" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (9 of ($s*) or (all of ($vx*) and 2 of ($s*)) or all of ($vf*))
}
