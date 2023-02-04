rule Mercurial {
    meta:
        author = "ditekSHen"
        description = "Detects Mercurial infostealer"
        cape_type = "Mercurial Infostealer Payload"
    strings:
        $x1 = "mercurial grabber" wide nocase
        $x2 = "\"text\":\"Mercurial Grabber |" wide
        $x3 = "/nightfallgt/mercurial-grabber" wide
        $s1 = "/LimerBoy/Adamantium-Thief/" ascii
        $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0" fullword wide
        $s3 = "StealCookies" fullword ascii
        $s4 = "StealPasswords" fullword ascii
        $s5 = "DetectDebug" fullword ascii
        $s6 = "CaptureScreen" fullword ascii
        $s7 = "WebhookContent" fullword ascii
        $s8 = /Grab(Token|Product|IP|Hardware)/ fullword ascii
        $p1 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}" fullword ascii wide
        $p2 = "mfa\\.[\\w-]{84}" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or 5 of ($s*) or (all of ($p*) and 3 of ($s*)))
}
