rule Bandook
{

	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/bandook"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        cape_type = "Bandook Payload"

    strings:
    		$a = "aaaaaa1|"
            $b = "aaaaaa2|"
            $c = "aaaaaa3|"
            $d = "aaaaaa4|"
			$e = "aaaaaa5|"
			$f = "%s%d.exe"
			$g = "astalavista"
			$h = "givemecache"
			$i = "%s\\system32\\drivers\\blogs\\*"
			$j = "bndk13me"



    condition:
    		all of them
}

rule BandookPayload {
    meta:
        author = "ditekshen"
        description = "Detects Bandook backdoor"
        cape_type = "Bandook Payload"
    strings:
        $s1 = "\"%sLib\\dpx.pyc\" \"%ws\" \"%ws\" \"%ws\" \"%ws\" \"%ws\"" fullword wide
        $s2 = "%s\\usd\\dv-%s.dat" fullword ascii
        $s3 = "%sprd.dat" fullword ascii
        $s4 = "%sfile\\shell\\open\\command" fullword ascii
        $s5 = "explorer.exe , %s" fullword ascii

        $f1 = "CaptureScreen" fullword ascii
        $f2 = "StartShell" fullword ascii
        $f3 = "ClearCred" fullword ascii
        $f4 = "GrabFileFromDevice" fullword ascii
        $f5 = "PutFileOnDevice" fullword ascii
        $f6 = "ChromeInject" fullword ascii
        $f7 = "StartFileMonitor" fullword ascii
        $f8 = "DisableMouseCapture" fullword ascii
        $f9 = "StealUSB" fullword ascii
        $f10 = "DDOSON" fullword ascii
        $f11 = "InstallMac" fullword ascii
        $f12 = "SendCam" fullword ascii

        $x1 = "RTC-TGUBP" fullword ascii
        $x2 = "AVE_MARIA" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 6 of ($f*) or (2 of ($s*) and 3 of ($f*)) or (all of ($x*) and (2 of ($f*) or 3 of ($s*))))
}
