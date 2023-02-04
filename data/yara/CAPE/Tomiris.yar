rule Tomiris {
    meta:
        author = "ditekSHen"
        description = "Detects Tomiris"
        cape_type = "Tomiris Payload"
    strings:
        $f1 = "main.workPath" ascii
        $f2 = "main.selfName" ascii
        $f3 = "main.infoServerAddr" ascii
        $f4 = "main.configFileName" ascii
        $s1 = "C:/Projects/go/src/Tomiris/main.go" ascii
        $s2 = "C:/GO/go1.16.2/src/os/user/lookup_windows.go" ascii
        $s3 = "C:\\GO\\go1.16.2" ascii
        $s4 = ".html.jpeg.json.wasm.webp/p/gf/p/kk1562515" ascii
        $s5 = "\" /ST 10:00alarm clockassistQueueavx512vbmi2avx512vnniwbad" ascii
        $s6 = "write /TR \" Value addr= alloc base  code= ctxt: curg= free  goid  jobs= list= m->p=" ascii
        $t1 = "SCHTASKS /DELETE /F /TN \"%s\"" ascii
        $t2 = "SCHTASKS /CREATE /SC DAILY /TN" ascii
        $t3 = "SCHTASKS /CREATE /SC ONCE /TN \"%s\" /TR \"%s\" /ST %s" ascii
        $t4 = "SCHTASKS /CREATE /SC ONCE /TN \"%s\" /TR \"'%s' %s\" /ST %s" ascii
        $r1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones" ascii
        $r2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($f*) and 3 of ($s*) and 2 of ($t*) and 1 of ($r*)) or (4 of ($s*) and 2 of ($t*) and 1 of ($r*)) or 12 of them)
}
