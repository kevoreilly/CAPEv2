rule Leivion {
    meta:
        author = "ditekSHen"
        description = "Detects Leivion"
        cape_type = "Leivion Payload"
    strings:
        $s1 = "/var/lib/veil/go/src/runtime/mem_windows.go" fullword ascii
        $s2 = "/var/lib/veil/go/src/internal/singleflight/singleflight.go" fullword ascii
        $s3 = "/var/lib/veil/go/src/net/http/sniff.go" fullword ascii
        $s4 = "/var/lib/veil/go/src/net/sendfile_windows.go" fullword ascii
        $s5 = "/var/lib/veil/go/src/os/exec_" ascii
        $s6 = "/var/lib/veil/go/src/runtime/mgcsweep.go" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
