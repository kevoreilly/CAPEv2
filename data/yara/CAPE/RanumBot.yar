rule RanumBot {
    meta:
        author = "ditekSHen"
        description = "Detects RanumBot / Windigo / GoStealer"
        cape_type = "RanumBot Payload"
    strings:
        // variant 1
        $f1 = "main.addSchedulerTaskSSH" fullword ascii
        $f2 = "main.attackRouter" fullword ascii
        $f3 = "main.decryptPassword" fullword ascii
        $f4 = "main.handleScanRequest" fullword ascii
        $f5 = "main.scanNetwork" fullword ascii
        $f6 = "main.extractCredentials" fullword ascii
        $s1 = "H_T= H_a= H_g= MB,  W_a= and  h_a= h_g= h_t= max= ptr  siz= tab= top= u_a= u_g=%s/16%s:%d%s:22+0330+0430+0530+0545+0630+0845+10" ascii
        $s2 = "<== as  at  fp= is  lr: of  on  pc= sp: sp=) = ) m=+Inf, n -Inf00%x112212343125: p=ABRTACDTACSTAEDTAESTAKDTAKSTALRMAWSTAhomAtoiCESTChamDashEESTGOGCJulyJuneKILLLEAFLisuMiaoModiNZDTNZSTNewaPIPEQUITSASTSEGVTERMThai" ascii
        $s3 = "W*struct { P *big.Int; Q *big.Int; G *big.Int; Y *big.Int; Rest []uint8 \"ssh:\\\"rest\\\"\" }" ascii
        $s4 = "policy=api,ftp,local,password,policy,read,reboot,sensitive,sniff,ssh,telnet,test,web,winbox,write" ascii
        $s5 = "/Users/alexander/go/src/mikrotik/winbox.go" ascii
        // variant 2
        $xf1 = "main.readConfig" fullword ascii
        $xf2 = "main.ensureRunningAsUser" fullword ascii
        $xf3 = "main.configRegPath" fullword ascii
        $xf4 = "main.oldConfigRegPath" fullword ascii
        $uf1 = "main.locateChrome" fullword ascii
        $uf2 = "main.decryptAndUploadProfile" fullword ascii
        $uf3 = "main.decryptCookies" fullword ascii
        $uf4 = "main.extractPasswords" fullword ascii
        $uf5 = "main.getFirefoxProfile" fullword ascii
        $uf6 = "main.postBrowsersData" fullword ascii
        $uf7 = "main.uploadFirefoxProfile" fullword ascii
        $uf8 = "main.zipFirefoxProfile" fullword ascii
        $uf9 = /main\.detect(Browsers|Chrome|Coccoc|Edge|Firefox|InternetExplorer|Opera|Yandex)/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($f*) or 4 of ($s*) or (2 of ($f*) and 2 of ($s*)) or (all of ($xf*) and 1 of ($uf*)) or 6 of ($uf*))
}
