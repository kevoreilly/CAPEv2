rule VanillaRAT {
    meta:
        author = "ditekSHen"
        description = "Detects VanillaRAT"
        cape_type = "VanillaRAT Payload"
    strings:
        $stub = "VanillaStub." ascii wide
        $s1 = "Client.Send: " wide
        $s2 = "Connected to chat" fullword wide
        $s3 = "GetStoredPasswords" fullword wide
        $s4 = "Started screen locker." fullword wide
        $s5 = "[<\\MOUSE>]" fullword wide
        $s6 = "YOUR SCREEN HAS BEEN LOCKED!" fullword wide
        $s7 = "record recsound" fullword wide
        $f1 = "<StartRemoteDestkop>d__" ascii
        $f2 = "<ConnectLoop>d__" ascii
        $f3 = "<Scan0>k__" ascii
        $f4 = "<RemoteShellActive>k__" ascii
        $f5 = "KillClient" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (($stub and (2 of ($s*) or 2 of ($f*))) or 6 of ($s*) or all of ($f*))
}
