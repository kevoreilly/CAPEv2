rule ClientMesh
{
    meta:
        author = "Kevin Breen <kevin@techanarchy.net>"
        ref = "http://malwareconfig.com/stats/ClientMesh"
        family = "torct"
        cape_type = "ClientMesh Payload"

    strings:
        $string1 = "machinedetails"
        $string2 = "MySettings"
        $string3 = "sendftppasswords"
        $string4 = "sendbrowserpasswords"
        $string5 = "arma2keyMass"
        $string6 = "keylogger"
        $conf = {00 00 00 00 00 00 00 00 00 7E}

    condition:
        all of them
}
