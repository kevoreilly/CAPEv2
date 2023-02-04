rule GDriveRAT {
    meta:
        author = "ditekSHen"
        description = "Detects GDriveRAT"
        cape_type = "GDriveRAT Payload"
    strings:
        $h1 = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart" fullword wide
        $h2 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36" fullword wide
        $h3 = "multipart/related; boundary=\"boundary_tag\"" fullword wide
        $h4 = "https://www.googleapis.com/drive/v3/files" fullword wide
        $s1 = "move gdrive.exe \"C:\\Users\\" fullword wide
        $s2 = "file_data" fullword ascii
        $s3 = "comp_id" fullword ascii
        $s4 = "file_name" fullword ascii
        $s5 = "refresh_token" fullword ascii
        $s6 = "commands" fullword ascii
        $s7 = "execute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 3 of ($h*) and 5 of ($s*)
}
