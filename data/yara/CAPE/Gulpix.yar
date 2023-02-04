import "pe"

rule Gulpix {
    meta:
        author = "ditekSHen"
        description = "Detects Gulpix backddor"
        cape_type = "Gulpix Payload"
    strings:
        $x1 = "MainServer.dll" fullword ascii
        $x2 = "NvSmartMax.dat" fullword wide
        $x3 = "NvSmartMax.dll" fullword wide
        $x4 = "http://+:80/FD873AC4-CF86-4FED-84EC-4BD59C6F17A7/" fullword wide
        $s1 = "IP retriever" fullword wide
        $s2 = "\\cmd.exe" fullword wide
        $s3 = "\\msnetwork-cache.db" fullword wide
        $s4 = "http://+:" wide
        $s5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" fullword wide
        // UAC Bypass
        $s6 = "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" ascii
        $s7 = "Got a unknown request for %ws" wide
        $s8 = "HttpReceiveRequestEntityBody failed with %lu" wide
        $s9 = "FD873AC4-CF86-4FED-84EC-4BD59C6F17A7" wide
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or 6 of ($s*) or (2 of ($x*) and 4 of ($s*)) or
             (
                 2 of them and
                 pe.exports("daemon") and
                 pe.exports("run") and
                 pe.exports("session") and
                 pe.exports("work")
            )
        )
}
