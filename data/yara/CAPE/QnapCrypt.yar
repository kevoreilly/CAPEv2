rule QnapCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects QnapCrypt/Lockedv1/Cryptfile2 ransomware"
        cape_type = "QnapCrypt Payload"
    strings:
        $go = "Go build ID:" ascii
        $s1 = "Encrypting %s..." ascii
        $s2 = "\\Start Menu\\Programs\\StartUp\\READMEV" ascii
        $s3 = "main.deleteRecycleBin" ascii
        $s4 = "main.encryptFiles" ascii
        $s5 = "main.antiVirtualBox" ascii
        $s6 = "main.antiVmware" ascii
        $s7 = "main.deleteShadows" ascii
        $s8 = "main.delUAC" ascii
        $s9 = "main.KillProcess" ascii
        $s10 = "main.delExploit" ascii
        $s11 = "main.encrypt" ascii
        $s12 = "main.ClearLogDownload" ascii
        $s13 = "main.ClearLog" ascii
        $s14 = "main.EndEncrypt" ascii
        $s15 = "main.RunFuckLogAndSoft" ascii
        $s16 = "main.ClearUsercache" ascii
        $s17 = "main.FirstDuty" ascii
        $s18 = ".lockedv1" ascii
        $s19 = "WSAStartup\\clear.bat\\ngrok.exe\\video.mp4" ascii
        $s20 = "net stop " ascii
    condition:
        uint16(0) == 0x5a4d and $go and 6 of ($s*)
}
