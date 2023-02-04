rule Macoute {
    meta:
        author = "ditekSHen"
        description = "Detects Macoute"
        cape_type = "Macoute Payload"
    strings:
        $s1 = "scp%s%s%s%s" ascii
        $s2 = "putfile %s %s" ascii
        $s3 = "pscp|%s|%s:%s" ascii
        $s4 = "connect %host %port\\n" ascii
        $s5 = "/ecoute/spool/%s-%lu" ascii
        $s6 = "<f n=\"%s\" s=\"%lu\" d=\"%d-%d-%d\"/>" ascii
        $s7 = "CMPT;%s;%s;%s;%s;%s" ascii
        $s8 = "%s\\apoScreen%lu.dll" ascii
        $s9 = "/cap/%s%lu.jpg" ascii
        $s10 = "INFO;%u;%u;%u;%d;%d;%d;%d;%d;%d;%d;%s" ascii
        $s11 = "SUBJECT: %s is comming!" ascii
        $s12 = "Content-type: multipart/mixed; boundary=\"#BOUNDARY#\"" ascii
        $s13 = "FROM: %s@yahoo.com" ascii
        $s14 = "<html><script language=\"JavaScript\">window.open(\"readme.eml\", null,\"resizable=no,top=6000,left=6000\")</script></html>" ascii
        $s15 = "<html><HEAD></HEAD><body bgColor=3D#ffffff><iframe src=3Dcid:THE-CID height=3D0 width=3D0></iframe></body></html>" ascii
    condition:
        uint16(0) == 0x5a4d and 10 of them
}
