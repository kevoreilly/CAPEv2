rule Sn0wLogger {
    meta:
        author = "ditekSHen"
        description = "Detects Sn0wLogger"
        cape_type = "Sn0wLogger Payload"
    strings:
        $s1 = "\\SnowP\\Example\\Secured\\" ascii
        $s2 = "{0}{3}Content-Type: {4}{3}Content-Disposition: form-data; name=\"{1}\"{3}{3}{2}{3}" wide
        $s3 = "\"encrypted_key\":\"(.*?)\"" fullword wide
        $s4 = "<SendToDiscord>d__" ascii
        $s5 = "_urlWebhook" ascii
        $r1 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}" fullword wide
        $r2 = "^\\w+([-+.']\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*$" fullword wide
        $r3 = "mfa\\.[\\w-]{84}" fullword wide
        $r4 = "(\\w+)=(\\d+)-(\\d+)$" fullword wide
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or (all of ($r*) and 2 of ($s*)) or 7 of them)
}
