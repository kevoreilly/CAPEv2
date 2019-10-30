rule AlienSpy
{
    meta:
        author = "Kevin Breen"
        ref = "http://malwareconfig.com/stats/AlienSpy"
        maltype = "Remote Access Trojan"
        filetype = "jar"
        cape_type = "AlienSpy Payload"

    strings:
        $PK = "PK"
        $MF = "META-INF/MANIFEST.MF"
    
        $a1 = "a.txt"
        $a2 = "b.txt"
        $a3 = "Main.class"
    
        $b1 = "ID"
        $b2 = "Main.class"
        $b3 = "plugins/Server.class"
    
        $c1 = "resource/password.txt"
        $c2 = "resource/server.dll"
    
        $d1 = "java/stubcito.opp"
        $d2 = "java/textito.isn"
    
        $e1 = "java/textito.text"
        $e2 = "java/resources.xsx"
    
        $f1 = "amarillo/asdasd.asd"
        $f2 = "amarillo/adqwdqwd.asdwf"

        $g1 = "config/config.perl"
        $g2 = "main/Start.class"
        
        $o1 = "config/config.ini"
        $o2 = "windows/windows.ini"
        $o3 = "components/linux.plsk"
        $o4 = "components/manifest.ini"
        $o5 = "components/mac.hwid"
        

    condition:
        $PK at 0 and $MF and
        (all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*) or all of ($e*) or all of ($f*) or all of ($g*) or any of ($o*))
}
