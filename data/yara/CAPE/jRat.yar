rule jRat
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/jRat"
		maltype = "Remote Access Trojan"
		filetype = "Java"
        cape_type = "jRat Payload"

    strings:
        $meta = "META-INF"
        $key = "key.dat"
        $conf = "config.dat"
 		$jra1 = "enc.dat"
		$jra2 = "a.class"
		$jra3 = "b.class"
		$jra4 = "c.class"
        $reClass1 = /[a-z]\.class/
        $reClass2 = /[a-z][a-f]\.class/

    condition:
       ($meta and $key and $conf and #reClass1 > 10 and #reClass2 > 10) or ($meta and $key and all of ($jra*))
}
