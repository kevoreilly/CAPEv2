rule StrongPity {
    meta:
        author = "ditekSHen"
        description = "Detects StrongPity"
        cape_type = "StrongPity Payload"
    strings:
        $s1 = "Boundary%08X" ascii wide
        $s2 = "Content-Disposition: form-data; name=\"file\";" fullword ascii
        $s3 = "%sfilename=\"%ls\"" fullword ascii
        $s4 = "name=%ls&delete=" fullword ascii
        $s5 = "Content-Type: application/octet-stream" fullword ascii
        $s6 = "cmd.exe /C ping" wide
        $s7 = "& rmdir /Q /S \"" wide
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
