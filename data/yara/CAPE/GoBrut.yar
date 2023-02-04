rule GoBrut {
    meta:
        author = "ditekSHen"
        description = "Detects unknown Go multi-bruteforcer bot (StealthWorker / GoBrut) against multiple systems: QNAP, MagOcart, WordPress, Opencart, Bitrix, Postgers, MySQL, Drupal, Joomla, SSH, FTP, Magneto, CPanel"
        cape_type = "GoBrut StealthWorker Payload"
    strings:
        $x1 = "/src/StealthWorker/Worker" ascii
        $x2 = "/go/src/Cloud_Checker/" ascii
        $x3 = "brutXmlRpc" ascii
        $s1 = "main.WPBrut" ascii
        $s2 = "main.WPChecker" ascii
        $s3 = "main.WooChecker" ascii
        $s4 = "main.StandartBrut" ascii
        $s5 = "main.StandartBackup" ascii
        $s6 = "main.WpMagOcartType" ascii
        $s7 = "main.StandartAdminFinder" ascii
        $w1 = "/WorkerQnap_brut/main.go" ascii
        $w2 = "/WorkerHtpasswd_brut/main.go" ascii
        $w3 = "/WorkerOpencart_brut/main.go" ascii
        $w4 = "/WorkerBitrix_brut/main.go" ascii
        $w5 = "/WorkerPostgres_brut/main.go" ascii
        $w6 = "/WorkerMysql_brut/main.go" ascii
        $w7 = "/WorkerFTP_brut/main.go" ascii
        $w8 = "/WorkerSSH_brut/main.go" ascii
        $w9 = "/WorkerDrupal_brut/main.go" ascii
        $w10 = "/WorkerJoomla_brut/main.go" ascii
        $w11 = "/WorkerMagento_brut/main.go" ascii
        $w12 = "/WorkerWHM_brut/main.go" ascii
        $w13 = "/WorkerCpanel_brut/main.go" ascii
        $w14 = "/WorkerPMA_brut/main.go" ascii
        $w15 = "/WorkerWP_brut/main.go" ascii
        $p1 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=cpanel" ascii
        $p2 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=ftpBrut" ascii
        $p3 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=mysql_b" ascii
        $p4 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=qnapBrt" ascii
        $p5 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=OCartBrt" ascii
        $p6 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=phpadmin" ascii
        $p7 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=bitrixBrt" ascii
        $p8 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=drupalBrt" ascii
        $p9 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=joomlaBrt" ascii
        $p10 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=htpasswdBrt" ascii
        $p11 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=magentoBrt" ascii
        $p12 = "%s/project/saveGood?host=%s&login=%s&password=%s&service=postgres_b" ascii
        $p13 = "AUTH_FORM=Y&TYPE=AUTH&USER_LOGIN=%s&USER_PASSWORD=%s&Login=&captcha_sid=&captcha_word=" ascii
        $p14 = "%qlog=%s&pwd=%s&wp-submit=Log In&redirect_to=%s/wp-admin/&testcookie=1" ascii
        $p15 = "name=%s&pass=%s&form_build_id=%s&form_id=user_login_form&op=Log" ascii
        $p16 = "username=%s&passwd=%s&option=com_login&task=login&return=%s&%s=1" ascii
        $v1_1 = "brutC" fullword ascii
        $v1_2 = "XmlRpc" fullword ascii
        $v1_3 = "shouldRetry$" ascii
        $v1_4 = "HttpC|%" ascii
        $v1_5 = "ftpH%_" ascii
        $v1_6 = "ssh%po" ascii
        $v1_7 = "?sevlyar/4-da" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f) and ((2 of ($x*) and 3 of ($s*)) or all of ($s*) or 6 of ($w*) or 6 of ($p*) or 6 of ($v1*) or 12 of them)
}
