rule KoadicJS {
    meta:
        author = "ditekSHen"
        description = "Koadic post-exploitation framework JS payload"
        cape_type = "KoadicJS Payload"
    strings:
        $s1 = "window.moveTo(-" ascii
        $s2 = "window.onerror = function(sMsg, sUrl, sLine) { return false; }" fullword ascii
        $s3 = "window.onfocus = function() { window.blur(); }" fullword ascii
        $s4 = "window.resizeTo(" ascii
        $s5 = "window.blur();" fullword ascii
        $hf1 = "<hta:application caption=\"no\" windowState=\"minimize\" showInTaskBar=\"no\"" fullword ascii
        $hf2 = "<hta:application caption=\"no\" showInTaskBar=\"no\" windowState=\"minimize\" navigable=\"no\" scroll=\"no\""
        $ht1 = "<hta:application" ascii
        $ht2 = "caption=\"no\"" ascii
        $ht3 = "showInTaskBar=\"no\"" ascii
        $ht4 = "windowState=\"minimize\"" ascii
        $ht5 = "navigable=\"no\"" ascii
        $ht6 = "scroll=\"no\"" ascii
    condition:
        all of ($s*) and (1 of ($hf*) or all of ($ht*))
}
