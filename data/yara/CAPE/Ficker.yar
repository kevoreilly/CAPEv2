rule Ficker {
    meta:
        author = "ditekSHen"
        description = "Detects Ficker infostealer"
        cape_type = "Ficker Payload"
    strings:
        $s1 = "JNOde\\" ascii
        $s2 = "\"SomeNone" fullword ascii
        $s3 = "kindmessage" fullword ascii
        $s4 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writting non-UTF-8 byte sequences" ascii
        $s5 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writing non-UTF-8 byte sequences" ascii
        $s6 = "(os error other os erroroperation interrruptedwrite zerotimed" ascii
        $s7 = "(os error other os erroroperation interruptedwrite zerotimed" ascii
        $s8 = "nPipeAlreadyExistsWouldBlockInvalidInputInvalidDataTimedOutWriteZeroInterruptedOtherN" fullword ascii
        $s9 = "_matherr(): %s in %s(%g, %g)  (retval=%g)" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
