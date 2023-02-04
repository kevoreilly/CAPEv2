rule Gasket {
    meta:
        author = "ditekSHen"
        description = "Detects Gasket"
        cape_type = "Gasket Payload"
    strings:
        $s1 = "main.checkGasket" ascii
        $s2 = "main.connectGasket" ascii
        $s3 = "/cert/trust/dev/stderr/dev/stdout/index.html" ascii
        $f1 = ".SetPingHandler." ascii
        $f2 = ".SetPongHandler." ascii
        $f3 = ".computeMergeInfo." ascii
        $f4 = ".computeDiscardInfo." ascii
        $f5 = ".readPlatformMachineID." ascii
        $f6 = ".(*Session).establishStream." ascii
        $f7 = ".(*Session).handleGoAway." ascii
        $f8 = ".(*Stream).processFlags." ascii
        $f9 = ".(*Session).handlePing." ascii
        $f10 = ".(*windowsService).Install." ascii
        $f11 = ".(*windowsService).Uninstall." ascii
        $f12 = ".(*windowsService).Status." ascii
        $f13 = ".getStopTimeout." ascii
        $f14 = ".DialContext." ascii
        $f15 = ".WriteControl." ascii
        $f16 = ".(*Server).authenticate." ascii
        $f17 = ".(*Server).ServeConn." ascii
        $f18 = ".(*TCPProxy).listen." ascii
        $f19 = ".UserPassAuthenticator.Authenticate." ascii
        $f20 = ".(*InfoPacket).XXX_" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 16 of ($f*))
}
