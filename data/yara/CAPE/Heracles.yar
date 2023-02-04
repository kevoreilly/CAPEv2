rule Heracles {
    meta:
        author = "ditekSHen"
        description = "Detects Heracles infostealer"
        cape_type = "Heracles Infostealer Payload"
    strings:
        $x1 = "aHR0cHM6Ly9uYWNrZXIudG9hbnNlY3UuY29tL3VwbG9hZHM/a2V5PX" wide
        $b1 = "XEdvb2dsZVxDaHJvbWVc" wide
        $b2 = "XEJyYXZlU29mdHdhcmVcQnJhdmUtQnJvd3Nlcl" wide
        $b3 = "XENvY0NvY1xCcm93c2VyX" wide
        $b4 = "VXNlciBEYXRh" wide
        $b5 = "RGVmYXVsdA" wide
        $b6 = "UHJvZmlsZQ" wide
        $b7 = "Q29va2llcw" wide
        $b8 = "TG9naW4gRGF0YQ" wide
        $b9 = "TG9jYWwgU3RhdGU" wide
        $b10 = "bG9jYWxzdGF0ZQ" wide
        $b11 = "bG9naW5kYXRh" wide
        $s1 = "encrypted_key" fullword wide
        $s2 = "<GetIpInfoAsync>d__" ascii
        $s3 = "<reqHTML>5__" ascii
        $s4 = "<idHardware>5__" ascii
        $s5 = "<profilePaths>5__" ascii
        $s6 = "<cookieFile>5__" ascii
        $s7 = "<loginDataFile>5__" ascii
        $s8 = "<localStateFile>5__" ascii
        $s9 = "<postData>5__" ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or 8 of ($s*) or (4 of ($b*) and 4 of ($s*)))
}
