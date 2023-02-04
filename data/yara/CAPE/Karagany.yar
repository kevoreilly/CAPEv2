rule KaraganyCore {
    meta:
        author = "ditekSHen"
        description = "Detects Karagany/xFrost core plugin"
        cape_type = "KaraganyCore Payload"
    strings:
        $s1 = "127.0.0.1" fullword ascii
        $s2 = "port" fullword ascii
        $s3 = "C:\\Windows\\System32\\Kernel32.dll" fullword ascii
        $s4 = "kernel32.dll" fullword ascii
        $s5 = "http" ascii
        $s6 = "Move" fullword ascii
        $s7 = "<supportedOS Id=\"{" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule KaraganyKeylogger {
    meta:
        author = "ditekSHen"
        description = "Detects Karagany/xFrost keylogger plugin"
        cape_type = "KaraganyKeylogger Payload"
    strings:
        $s1 = "__klg__" fullword wide
        $s2 = "__klgkillsoft__" fullword wide
        $s3 = "CLIPBOARD_PASTE" wide
        $s4 = "%s\\k%d.txt" wide
        $s5 = "\\Update\\Tmp" wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule KaraganyScreenUtil {
    meta:
        author = "ditekSHen"
        description = "Detects Karagany/xFrost ScreenUtil module"
        cape_type = "KaraganyScreenUtil Payload"
    strings:
        $s1 = "__pic__" ascii wide
        $s2 = "__pickill__" ascii wide
        $s3 = "\\picture.png" fullword wide
        $s4 = "%d.jpg" wide
        $s5 = "\\Update\\Tmp" wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule KaraganyListrix {
    meta:
        author = "ditekSHen"
        description = "Detects Karagany/xFrost Listrix module"
        cape_type = "KaraganyListrix Payload"
    strings:
        $s1 = "\\Update\\Tmp\\" wide
        $s2 = "*pass*.*" fullword wide
        $s3 = ">> NUL" wide
        $s4 = "%02d.%02d.%04d %02d:%02d" wide
        $s5 = "/c del" wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
