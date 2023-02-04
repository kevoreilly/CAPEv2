rule MarkiRAT {
    meta:
        author = "ditekSHen"
        description = "Detects MarkiRAT"
        cape_type = "MarkiRAT Payload"
    strings:
        $pdb = "\\mfcmklg.pdb" ascii
        $s1 = "runinhome Completed" wide
        $s2 = "ERROR find next file<br>" wide
        $s3 = "<br><mark>Hello: %s</mark>" wide
        $s4 = "<br><mark>CLIPBOARD[" wide
        $s5 = "@userhome@" wide
        $s6 = "Global\\{2194ABA1-BFFA-4e6b-8C26-D1BB20190312}" wide
        $s7 = "taskkill /im svehost.exe /t /f" fullword ascii
        $s8 = "taskkill /im keepass.exe /t /f" fullword ascii
        $ba = /bitsadmin \/(addfile|cancel|SetPriority|resume)/ ascii wide
        $c1 = "/ech/client.php?u=" wide
        $c2 = "/up/uploadx.php?u=" wide
        $c3 = "/ech/echo.php?req=rr&u=" wide
        $c4 = "/ech/rite.php" wide
        $c5 = "http://microsoft.com-view.space/i.php?u=" wide
        $c6 = "Content-Disposition: form-data; name=\"uploadedfile\"; filename=\"" ascii
    condition:
        uint16(0) == 0x5a4d and (($pdb and any of them) or (5 of ($s*)) or (3 of ($c*)) or ((#ba > 3 and 4 of them)))
}
