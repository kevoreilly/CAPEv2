rule Rietspoof {
    meta:
        author = "ditekshen"
        description = "Rietspoof payload"
        cape_type = "Rietspoof payload"
    strings:
        $c1 = "%s%s%s USER: user" fullword ascii
        $c2 = "cmd /c %s" fullword ascii
        $c3 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(" ascii
        $c4 = "WScript.Quit" fullword ascii
        $c5 = "CPU: %s(%d)" fullword ascii
        $c6 = "RAM: %lld Mb" fullword ascii
        $c7 = "data.dat" fullword ascii
        $c8 = "%s%s%s USER:" ascii

        $v1_1 = ".vbs" ascii
        $v1_2 = "HELLO" ascii
        $v1_3 = "Wscript.Sleep" ascii
        $v1_4 = "User-agent:Mozilla/5.0 (Windows; U;" ascii

        $v2_1 = "Xjoepxt!" ascii
        $v2_2 = "Content-MD5:%s" fullword ascii
        $v2_3 = "M9h5an8f8zTjnyTwQVh6hYBdYsMqHiAz" fullword ascii
        $v2_4 = "GET /%s?%s HTTP/1.1" fullword ascii
        $v2_5 = "GET /?%s HTTP/1.1" fullword ascii

        $pdb1 = "\\techloader\\loader\\loader.odb" ascii wide
        $pdb2 = "\\loader\\Release\\loader_v1.0.pdb" ascii wide
    condition:
        uint16(0) == 0x5a4d and (7 of ($c*) and (3 of ($v*) or 1 of ($pdb*)))
}
