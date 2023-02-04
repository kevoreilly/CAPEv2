rule SunCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects SunCrypt ransomware"
        cape_type = "SunCrypt Payload"
    strings:
        $s1 = "-noshares" fullword wide
        $s2 = "-nomutex" fullword wide
        $s3 = "-noreport" fullword wide
        $s4 = "-noservices" fullword wide
        $s5 = "$Recycle.bin" fullword wide
        $s6 = "YOUR_FILES_ARE_ENCRYPTED.HTML" fullword wide
        $s7 = "\\\\?\\%c:" fullword wide
        $s8 = "locker.exe" fullword ascii
        $s9 = "DllRegisterServer" fullword ascii
        $g1 = "main.EncFile" fullword ascii nocase
        $g2 = "main.detectName" fullword ascii nocase
        $g3 = "main.detectIP" fullword ascii nocase
        $g4 = "main.detectDebugProc" fullword ascii nocase
        $g5 = "main.Bypass" ascii nocase
        $g6 = "main.allocateMemory" fullword ascii nocase
        $g7 = "main.killAV" fullword ascii nocase
        $g8 = "main.disableShadowCopy" fullword ascii nocase
        $g9 = "main.(*windowsDrivesModel).LoadDrives" fullword ascii nocase
        $g10 = "main.IsFriends" fullword ascii nocase
        $g11 = "main.walkMsg" fullword ascii nocase
        $g12 = "main.makeSecretMessage" fullword ascii nocase
        $g13 = "main.stealFiles" fullword ascii nocase
        $g14 = "main.newKey" fullword ascii nocase
        $g15 = "main.openBrowser" fullword ascii nocase
        $g16 = "main.killProc" fullword ascii nocase
        $g17 = "main.selfRemove" fullword ascii nocase
        $m1 = "<h2>\\x20Offline\\x20HowTo\\x20</h2>\\x0a\\x09\\x09\\x09\\x09<p>Copy\\x20&\\x20Paste\\x20this\\x20message\\x20to" ascii
        $m2 = "\\x20restore\\x20your\\x20files." ascii
        $m3 = "\\x20your\\x20documents\\x20and\\x20files\\x20encrypted" ascii
        $m4 = "\\x20lose\\x20all\\x20of\\x20your\\x20data\\x20and\\x20files." ascii
        $m5 = ",'/#/client/','<h2>\\x20Whats\\x20Happen" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or 6 of ($g*) or 3 of ($m*))
}
