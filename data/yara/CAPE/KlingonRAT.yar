rule KlingonRAT {
    meta:
        author = "ditekSHen"
        description = "Detects KlingonRAT"
        cape_type = "KlingonRAT Payload"
    strings:
        $go = "Go build ID:" ascii
        $s1 = "/UCRelease/src/client/uac/once/"
        $s2 = "%T\\AppData\\Local\\Windows Update\\"
        $s3 = "%TSoftware\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
        $s4 = "wmic /namespace:'\\\\root\\subscription' PATH"
        $s5 = "C:\\Windows\\System32\\fodhelper.exeCaption,ParentProcessId,ProcessId"
        $s6 = "ldpro.exelsass.exeluall.exeluspt.exe"
        $s7 = "scangui.exedeps/lsass.exeetrustcipe.exefile"
        $s8 = "alogserv.exeaplica32.exeapvxdwin.exeatro55en.exeautodown.exeavconsol.exeavgserv9.exeavkwctl9.exeavltmain.exeavpdos32.exeavsynmgr.exeavwupd32.exeavwupsrv.exe"
        $c1 = "%s/keyLogger?machineId=%s" ascii
        $c2 = "%s/stealer?machineId=%s" ascii
        $c3 = "%s/lsass?machineId=%s" ascii
        $c4 = "%s/logger?machineId=%s" ascii
        $c5 = "%s/machineInfo?machineId=%s" ascii
        $c6 = "failurehttps://%s:%d/botif-modified-sinceillegal" ascii
    condition:
        uint16(0) == 0x5a4d and ($go) and (3 of ($c*) or 5 of ($s*) or (3 of ($s*) and 1 of ($c*)))
}
