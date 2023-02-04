rule TrickbotModule {
    meta:
        author = "ditekshen"
        description = "Detects Trickbot modules"
        cape_type = "TrickbotModule Payload"
    strings:
        $mc = "<moduleconfig>" ascii
        $s1 = "<autostart>" ascii
        $s2 = "<nohead>" ascii
        $s3 = "<needinfo" ascii
        $s4 = "<conf ctl" ascii
        $s5 = "<limit>" ascii
        $w1 = "<sys>yes</sys>" ascii
        $w2 = "<sys>no</sys>" ascii
        $w3 = "<autostart>yes</autostart>" ascii
        $w4 = "<autostart>no</autostart>" ascii
        $w5 = "<nohead>yes</nohead>" ascii
        $w6 = "<nohead>no</nohead>" ascii
        $w7 = /<limit>\d+<\/limit>/ ascii
        $w8 = "<moduleconfig> </moduleconfig" ascii
    condition:
        uint16(0) == 0x5a4d and $mc and (2 of ($s*) or (1 of ($s*) and 1 of ($w*)) or 1 of ($w*))
}
