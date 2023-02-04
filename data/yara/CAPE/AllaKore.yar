rule AllaKore {
     meta:
        author = "ditekSHen"
        description = "Detects AllaKore"
        cape_type = "AllaKore Payload"
    strings:
        $x1 = "AllaKore Remote - Chat" fullword wide
        $x2 = "AllaKore Remote - Share Files" fullword wide
        $x3 = "CYRUS - Chat" fullword wide
        $x4 = "CYRUS - Share Files" fullword wide
        $x5 = "<|REDIRECT|><|GETFOLDERS|>" fullword wide
        $x6 = "<|REDIRECT|><|DOWNLOADFILE|>" fullword wide
        $x7 = "<|REDIRECT|><|WHEELMOUSE|>" fullword wide
        $x8 = "<|REDIRECT|><|SETMOUSE" wide
        $x9 = "<|CHECKIDPASSWORD|>" fullword wide
        $x10 = "<|KEYBOARDSOCKET|>" fullword wide
        $x11 = "<|REDIRECT|><|CLIPBOARD|>" fullword wide
        $x12 = "<|IDEXISTS!REQUESTPASSWORD|>" fullword wide
        $x13 = "<|GETFULLSCREENSHOT|>" fullword wide
        $x14 = "<|MAINSOCKET|>" fullword ascii
        $s1 = "You can not connect with yourself!" wide
        $s2 = "Waiting for authentication..." wide
        $s3 = "Connected support!" wide
        $s4 = "ID does nor exists." wide
        $s5 = "Finding the ID..." wide
        $s6 = "PC is Busy!" wide
        $s7 = "Upload &  Execute" fullword ascii
        $s8 = "Download file selected" fullword ascii
        $s9 = "CaptureKeys_TimerTimer" fullword ascii
        $s10 = "Remote File Manager" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($x*) or 4 of ($s*) or (3 of ($s*) and 2 of ($x*)))
}
