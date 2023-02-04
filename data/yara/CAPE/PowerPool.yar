rule PowerPool {
    meta:
        author = "ditekshen"
        description = "PowerPool Stage 1 Backdoor Payload"
        cape_type = "PowerPool Payload"
    strings:
        $str1 = "cmd /c powershell.exe " wide
        $str2 = "rar.exe a -r %s.rar" wide
        $str3 = "MyDemonMutex%d" wide
        $str4 = "CMD COMMAND EXCUTE ERROR!" ascii
        $str5 = "/?id=%s&info=%s" wide
        $str6 = "MyScreen.jpg" wide
        $str7 = "proxy.log" wide
    condition:
        uint16(0) == 0x5A4D and 5 of them
}
