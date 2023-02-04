rule NanoCore
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        ref = "http://malwareconfig.com/stats/NanoCore"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        cape_type = "NanoCore Payload"

    strings:
        $a = "NanoCore"
        $b = "ClientPlugin"
        $c = "ProjectData"
        $d = "DESCrypto"
        $e = "KeepAlive"
        $f = "IPNETROW"
        $g = "LogClientMessage"
		$h = "|ClientHost"
		$i = "get_Connected"
		$j = "#=q"
        $key = {43 6f 24 cb 95 30 38 39}


    condition:
        6 of them
}
