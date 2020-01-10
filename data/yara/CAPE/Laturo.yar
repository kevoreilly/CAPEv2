rule Laturo {
    meta:
        author = "ditekshen"
        description = "Laturo information stealer payload"
        cape_type = "Laturo Payload"
    strings:
        $str1 = "cmd.exe /c ping 127.0.0.1" ascii wide
        $str2 = "cmd.exe /c start" ascii wide
        $str3 = "\\RapidLoader\\" ascii
        $str4 = "loader/gate.php" ascii wide
        $str5 = "Hwid:" ascii wide
        $str6 = "Special:" ascii wide
        $str7 = "logs=%s" ascii
        $data1 = "cookies.%u.txt" nocase ascii wide
        $data2 = "passwords.%u.txt" nocase ascii wide
        $data3 = "credentials.%u.txt" nocase ascii wide
        $data4 = "cards.%u.txt" nocase ascii wide
        $data5 = "autofill.%u.txt" nocase ascii wide
        $data6 = "loginusers.vdf" ascii wide
        $data7 = "screenshot.bmp" nocase ascii wide
        $data8 = "webcam.bmp" nocase ascii wide
    condition:
        uint16(0) == 0x5a4d and 5 of ($str*) and 1 of ($data*)
}
