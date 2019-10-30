rule Plasma
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        ref = "http://malwareconfig.com/stats/Plasma"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        cape_type = "Plasma Payload"

    strings:
        $a = "Miner: Failed to Inject." wide
        $b = "Started GPU Mining on:" wide
        $c = "BK: Hard Bot Killer Ran Successfully!" wide
        $d = "Uploaded Keylogs Successfully!" wide
        $e = "No Slowloris Attack is Running!" wide
        $f = "An ARME Attack is Already Running on" wide
        $g = "Proactive Bot Killer Enabled!" wide
        $h = "PlasmaRAT" wide ascii
        $i = "AntiEverything" wide ascii

    condition:
        all of them
}