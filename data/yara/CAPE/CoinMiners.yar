rule CoinMiner01 {
    meta:
        author = "ditekSHen"
        description = "Detects coinminer payload"
        cape_type = "CoinMiner01 Payload"
    strings:
        $s1 = "-o pool." ascii wide
        $s2 = "--cpu-max-threads-hint" ascii wide
        $s3 = "-P stratum" ascii wide
        $s4 = "--farm-retries" ascii wide
        $dl = "github.com/ethereum-mining/ethminer/releases/download" ascii wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or ($dl))
}

rule CoinMiner02 {
    meta:
        author = "ditekSHen"
        description = "Detects coinmining malware"
        cape_type = "CoinMiner02 Payload"
    strings:
        $s1 = "%s/%s (Windows NT %lu.%lu" fullword ascii
        $s2 = "\\Microsoft\\Libs\\WR64.sys" wide
        $s3 = "\\\\.\\WinRing0_" wide
        $s4 = "pool_wallet" ascii
        $s5 = "cryptonight" ascii
        $s6 = "mining.submit" ascii
        $c1 = "stratum+ssl://" ascii
        $c2 = "daemon+http://" ascii
        $c3 = "stratum+tcp://" ascii
        $c4 = "socks5://" ascii
        $c5 = "losedaemon+https://" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) and 1 of ($c*))
}

rule CoinMiner03 {
    meta:
        author = "ditekSHen"
        description = "Detects coinmining malware"
        cape_type = "CoinMiner03 Payload"
    strings:
        $s1 = "UnVzc2lhbiBTdGFuZGFyZCBUaW1l" wide
        $s2 = "/xmrig" wide
        $s3 = "/gminer" wide
        $s4 = "-o {0} -u {1} -p {2} -k --cpu-priority 0 --threads={3}" wide
        $s5 = "--algo ethash --server" wide
        $s6 = "--algo kawpow --server" wide
        $cnc1 = "/delonl.php?hwid=" fullword wide
        $cnc2 = "/gateonl.php?hwid=" fullword wide
        $cnc3 = "&cpuname=" fullword wide
        $cnc4 = "&gpuname=" fullword wide
        $cnc5 = "{0}/gate.php?hwid={1}&os={2}&cpu={3}&gpu={4}&dateinstall={5}&gpumem={6}" fullword wide
        $cnc6 = "/del.php?hwid=" fullword wide
        $f1 = "<StartGpuethGminer>b__" ascii
        $f2 = "<StartGpuetcGminer>b__" ascii
        $f3 = "<StartGpurvnGminer>b__" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($cnc*) or (2 of ($f*) and (1 of ($s*) or 1 of ($f*))) or all of ($f*) or 5 of ($s*))
}

rule CoinMiner04 {
    meta:
        author = "ditekSHen"
        description = "Detects coinmining malware"
        cape_type = "CoinMiner04 Payload"
    strings:
        $s1 = "createDll" fullword ascii
        $s2 = "getTasks" fullword ascii
        $s3 = "SetStartup" fullword ascii
        $s4 = "loadUrl" fullword ascii
        $s5 = "Processer" fullword ascii
        $s6 = "checkProcess" fullword ascii
        $s7 = "runProcess" fullword ascii
        $s8 = "createDir" fullword ascii
        $cnc1 = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0" fullword wide
        $cnc2 = "?hwid=" fullword wide
        $cnc3 = "?timeout=1" fullword wide
        $cnc4 = "&completed=" fullword wide
        $cnc5 = "/cmd.php" wide
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) and 1 of ($cnc*))
}
