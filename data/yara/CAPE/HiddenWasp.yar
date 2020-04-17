rule HiddenWasp {
    meta:
        author = "ditekshen"
        description = "HiddenWasp backdoor payload"
        cape_type = "HiddenWasp payload"
    strings:
        $x1 = "I_AM_HIDDEN" fullword ascii
        $x2 = "HIDE_THIS_SHELL" fullword ascii
        $x3 = "NewUploadFile" ascii
        $x4 = "fake_processname" ascii
        $x5 = "swapPayload" ascii
        $x6 = /Trojan-(Platform|Machine|Hostname|OSersion)/ fullword ascii
        $s1 = "FileOpration::GetFileData" fullword ascii
        $s2 = "FileOpration::NewUploadFile" fullword ascii
        $s3 = "Connection::writeBlock" fullword ascii
        $s4 = /hiding_(hidefile|enable_logging|hideproc|makeroot)/ fullword ascii
        $s5 = "Reverse-Port" fullword ascii
        $s6 = "hidden_services" fullword ascii
        $s7 = "check_config" fullword ascii
        $s8 = "__data_start" fullword ascii
        $s9 = /patch_(suger_lib|ld|lib)/ fullword ascii
        $s10 = "hexdump -ve '1/1 \"%%.2X\"' %s | sed \"s/%s/%s/g\" | xxd -r -p > %s.tmp"
    condition:
        uint16(0) == 0x457f and (4 of ($x*) or all of ($s*) or (3 of ($x*) and 5 of ($s*)))
}
