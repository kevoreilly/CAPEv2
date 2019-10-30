rule PoisonIvy
{
	// Modified for CAPE in 2017/03
    meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/PoisonIvy"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        cape_type = "PoisonIvy Payload"

    strings:
    	//$stub = {04 08 00 53 74 75 62 50 61 74 68 18 04}
    	$stub = "StubPath"
        $string1 = "CONNECT %s:%i HTTP/1.0"
        $string2 = "ws2_32"
        $string3 = "cks=u"
        $string4 = "thj@h"
        //$string5 = "advpack"
        $regvalue1 = "SOFTWARE\\Classes\\http\\shell\\open\\command"
        $regvalue2 = "Software\\Microsoft\\Active Setup\\Installed Components\\"
    condition:
		//$stub at 0x1620 and all of ($string*) or (all of them)
        all of ($string*) or ($stub and all of ($regvalue*))
}
