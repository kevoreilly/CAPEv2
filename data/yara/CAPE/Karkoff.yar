rule Karkoff {
    meta:
        author = "ditekSHen"
        description = "Detects Karkoff"
        cape_type = "Karkoff Payload"
    strings:
        $x1 = "C:\\Windows\\Temp\\MSEx_log.txt" fullword wide
        $x2 = "CMD.exe" fullword wide
        $x3 = "Karkoff.ProjectInstaller.resources" fullword ascii
        $s1 = /try\shttp(s)?\s(ip|domain)/ fullword wide
        $s2 = "Reg cleaned!" fullword wide nocase
        $s3 = "Content-Disposition: form-data; name=\"{1}\"" fullword wide
        $s4 = "^[A-Fa-f0-9]{8}-([A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}$" fullword wide
        $s5 = "new backdoor" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or 4 of ($s*) or (2 of ($x*) and 2 of ($s*)))
}
