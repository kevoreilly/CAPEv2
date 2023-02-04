rule Parallax {
    meta:
        author = "ditekSHen"
        description = "Detects Parallax RAT"
        cape_type = "Parallax RAT Payload"
    strings:
       $s1 = "[Clipboard End]" fullword wide
       $s2 = "[Ctrl +" fullword wide
       $s3 = "[Alt +" fullword wide
       $s4 = "Clipboard Start" wide
       $s5 = "(Wscript.ScriptFullName)" wide
       $s6 = "CSDVersion" fullword ascii
       $s7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
