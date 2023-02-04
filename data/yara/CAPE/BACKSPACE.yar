rule BACKSPACE {
    meta:
        author = "ditekshen"
        description = "BACKSPACE backdoor payload"
        cape_type = "BACKSPACE payload"
    strings:
        $s1 = "Software\\Microsoft\\PnpSetup" ascii wide
        $s2 = "Mutex_lnkword_little" ascii wide
        $s3 = "(Prxy%c-%s:%u)" fullword ascii
        $s4 = "(Prxy-No)" fullword ascii
        $s5 = "/index.htm" fullword ascii
        $s6 = "CONNECT %s:%d" ascii
        $s7 = "\\$NtRecDoc$" fullword ascii
        $s8 = "qazWSX123$%^" ascii
        $s9 = "Software\\Microsoft\\Core" ascii wide
        $s10 = "Mutex_lnkch" ascii wide
        $s11 = "Event__lnkch__" ascii wide
        $s12 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Win32)" fullword ascii
        $s13 = "User-Agent: Mozilla/5.00 (compatible; MSIE 6.0; Win32)" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}
