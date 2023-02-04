rule VirLock {
    meta:
        author = "ditekSHen"
        description = "Detects VirLock ransomware"
        cape_type = "VirLock Payload"
    strings:
        $x1 = "BThere are two ways to pay a fine:" fullword wide
        $x2 = "^Es gibt zwei M" fullword wide
        $x3 = "glichkeiten, eine Strafe zahlen." fullword wide
        $x4 = /usertile\d+\.bmp/ fullword wide
        $s1 = "WinSock 2.0" fullword ascii
        $s2 = "Running" fullword ascii
        $s3 = "echo WScript.Sleep(50)>%TEMP%/file.vbs" fullword ascii
        $s4 = "cscript %TEMP%/file.vbs" fullword ascii
        $s5 = "del /F /Q file.js" fullword ascii
        $s6 = "del /F /Q %1" fullword ascii
        $s7 = "del /F /Q %0" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and ((2 of ($x*) and 2 of ($s*)) or (5 of ($s*) and 1 of ($x*)))) or (8 of them)
}
