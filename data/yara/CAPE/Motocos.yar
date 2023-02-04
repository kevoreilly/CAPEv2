rule Motocos {
    meta:
        author = "ditekSHen"
        description = "Detects Motocos ransomware"
        cape_type = "Motocos Payload"
    strings:
        $s1 = "Block Investigation Tools" wide
        $s2 = "powershell.exe,taskmgr.exe,procexp.exe,procmon.exe" wide
        $s3 = "google.com,youtube.com,baidu.com,facebook.com,amazon.com,360.cn,yahoo.com,wikipedia.org,zoom.us,live.com,reddit.com,netflix.com,microsoft.com,instagram.com,vk.com," wide
        $s4 = "START ----" wide
        $s5 = "TEngine.Clear_EventLog_Result" wide
        $s6 = "TEngine.EncryptLockFiles" wide
        $s7 = "TEngine.CleanShadowFiles" wide
        $s8 = "TDNSUtils.SendCommand" wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
