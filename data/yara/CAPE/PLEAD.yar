rule PLEADLinux {
    meta:
        author = "ditekshen"
        description = "PLEAD Linux payload"
        cape_type = "PLEAD Linux Payload"
    strings:
        $x1 = "CFileTransfer" ascii
        $x2 = "CFileManager" ascii
        $x3 = "CPortForward" ascii
        $x4 = "CPortForwardManager" ascii
        $x5 = "CRemoteShell" ascii
        $x6 = "CSockClient" ascii

        $s1 = "/proc/self/exe" fullword ascii
        $s2 = "/bin/sh" fullword ascii
        $s3 = "echo -e '" ascii
        $s4 = "%s       <DIR>   %s" ascii
        $s5 = "%s       %lld    %s" ascii
        $s6 = "Files: %d                Size: %lld" ascii
        $s7 = "Dirs: %d" ascii
        $s8 = "%s(%s)/" ascii
        $s9 = "%s %s %s %s" ascii
    condition:
    uint16(0) == 0x457f and (all of ($x*) or all of ($s*) or 12 of them)
}
