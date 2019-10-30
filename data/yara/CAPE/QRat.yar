rule QRat
{
    meta:
        author = "Kevin Breen @KevTheHermit"
        ref = "http://malwareconfig.com"
        maltype = "Remote Access Trojan"
        filetype = "jar"
        cape_type = "QRat Payload"
        
    strings:
        $a0 = "e-data"
        $a1 = "quaverse/crypter"
        $a2 = "Qrypt.class"
        $a3 = "Jarizer.class"
        $a4 = "URLConnection.class"
        
        
    condition:
        4 of them


}