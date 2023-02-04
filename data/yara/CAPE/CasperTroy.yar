rule CasperTroy {
    meta:
        author = "ditekSHen"
        description = "Detects CasperTroy payload"
        cape_type = "CasperTroy Payload"
    strings:
        $s1 = "DllTroy.dll" fullword ascii
        $s2 = "Content-Disposition: form-data; name=\"image\"; filename=\"title.gif\"" fullword ascii
        $s3 = "Content-Disposition: form-data; name=\"COOKIE_ID\"" fullword ascii
        $s4 = "Content-Disposition: form-data; name=\"PHP_SESS_ID\"" fullword ascii
        $s5 = "Content-Disposition: form-data; name=\"SESS_ID\"" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
