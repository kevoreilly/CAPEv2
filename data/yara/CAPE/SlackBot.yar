rule SlackBot {
    meta:
        author = "ditekSHen"
        description = "Detects SlackBot"
        cape_type = "SlackBot Payload"
    strings:
        $x1 = "lp0o4bot v" ascii
        $x2 = "slackbot " ascii
        $s1 = "cpu: %lumhz %s, uptime: %u+%.2u:%.2u, os: %s" fullword ascii
        $s2 = "%s, running for %u+%.2u:%.2u" fullword ascii
        $s3 = "PONG :%s" fullword ascii
        $s4 = "PRIVMSG %s :%s" fullword ascii
        $s5 = "Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)" fullword ascii
        $m1 = "saving %s to %s" ascii
        $m2 = "visit number %u failed" ascii
        $m3 = "sending %s packets of %s bytes to %s with a delay of %s" ascii
        $m4 = "file executed" ascii
        $m5 = "packets sent" ascii
        $m6 = "upgrading to %s" ascii
        $m7 = "rebooting..." ascii
        $c1 = "!@remove" fullword ascii
        $c2 = "!@restart" fullword ascii
        $c3 = "!@reboot" fullword ascii
        $c4 = "!@rndnick" fullword ascii
        $c5 = "!@exit" fullword ascii
        $c6 = "!@sysinfo" fullword ascii
        $c7 = "!@upgrade" fullword ascii
        $c8 = "!@login" fullword ascii
        $c9 = "!@run" fullword ascii
        $c10 = "!@webdl" fullword ascii
        $c11 = "!@cycle" fullword ascii
        $c12 = "!@clone" fullword ascii
        $c13 = "!@visit" fullword ascii
        $c14 = "!@udp" fullword ascii
        $c15 = "!@nick" fullword ascii
        $c16 = "!@say" fullword ascii
        $c17 = "!@quit" fullword ascii
        $c18 = "!@part" fullword ascii
        $c19 = "!@join" fullword ascii
        $c20 = "!@raw" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or all of ($s*) or all of ($m*) or (10 of ($c*) and (1 of ($x*) or 3 of ($s*) or 2 of ($m*))))
}
