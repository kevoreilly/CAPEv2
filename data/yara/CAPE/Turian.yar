/* Hunt Result
   MD5   : c57135e591c824e99572ea2cc42bfd8c
   SHA1  : a505b99f4f6d74cc3134776e1d335d41106b6c8f
   SHA256: d1218ab9d608ee0212e880204e4d7d75f29f03b77248bca7648d111d67405759
   Domain: windowsupdate[.]dyndns[.]info
   IP    : 58[.]158[.]177[.]102
*/

rule Turian {
    meta:
        author = "ditekSHen"
        description = "Hunt for Turian / Qurian"
        cape_type = "Turian Payload"
    strings:
        $s1 = "%s a -m5 -hp1qaz@WSX3edc -r %s %s\\*.*" ascii wide
        $s2 = "%s a -m5 -hpMyHost-1 -r %s %s\\*.*" ascii wide
        $s3 = "%s a -m5 -hp1qaz@WSX3edc -ta%04d%02d%02d000000 -r %s c:" ascii wide
        $s4 = "%s a -m5 -hpMyHost-1 -ta%04d%02d%02d000000 -r %s c:"
        $s5 = "cmd /c dir /s /O:D %s>>\"%s\"" ascii wide
        $s6 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v %s /t REG_SZ /d \"%s\" /f" fullword ascii
        $s7 = "Not Connect!" fullword ascii
        $p1 = "RECYCLER\\S-1-3-33-854245398-2067806209-0000980848-2003\\" ascii wide
        $p2 = "%sRECYCLER.{S-1-3-33-854245398-2067806209-0000980848-2003}\\" ascii wide
        $p3 = "\\RECYCLER.{S-1-3-33-854245398-2067806209-0000980848-2003}\\" ascii wide
        $p4 = "\\RECYCLER.{645ff040-5081-101b-9f08-00aa002f954e}\\" ascii wide
        $p5 = "%sRECYCLER.{645ff040-5081-101b-9f08-00aa002f954e}\\" ascii wide
        $c1 = "CONNECT %s:%u HTTP/1." ascii wide
        $c2 = "User-Agent: Mozilla/4.0" ascii wide
        $m1 = "winsupdatetw" fullword ascii wide
        $m2 = "clientsix" fullword ascii wide
        $m3 = "updatethres" fullword ascii wide
        $m4 = "uwatchdaemon" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or (all of ($c*) and (2 of ($s*) or 1 of ($m*) or 1 of ($p*))) or (1 of ($m*) and 1 of ($s*) and (1 of ($c*) or 1 of ($p*))))
}
