rule MyKings 
{
    meta:
        author = "YungBinary"
        description = "https://x.com/YungBinary/status/1981108948498333900"
        cape_type = "MyKings Payload"
    strings: 
        $s1 = "login.php?uid=0" wide
        $s2 = "download.txt?rnd=" wide
        $s3 = "AcceptOK" ascii
        $s4 = "winsta0\\default" wide
        $s5 = "base64_ip.txt" wide
        $s6 = { 70 00 6F 00 77 00 65 00 72 00 74 00 6F 00 6F 00 6C 00 00 00 6B 00 61 00 73 00 70 00 65 00 72 00 73 00 6B 00 79 }
        $s7 = { 53 00 61 00 66 00 65 00 00 00 00 00 45 00 73 00 65 00 74 }
        $s8 = { 4E 00 6F 00 64 00 33 00 32 00 00 00 4D 00 61 00 6C 00 77 00 61 00 72 00 65 }
        $s9 = "Custom C++ HTTP Client/1.0" wide
        $s10 = "/ru \"SYSTEM\" /f" ascii
        $s11 = "cmd.exe /C timeout /t 1 & del " wide
        $s12 = "/login.aspx?uid=0" wide
        $s13 = "cmd-230812.ru" base64
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*))
}
