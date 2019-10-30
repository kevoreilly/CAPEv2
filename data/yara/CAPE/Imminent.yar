rule Imminent
{
    meta:
        author = "kevoreilly"
        description = "Imminent Payload"
        cape_type = "Imminent Payload"
    strings:
        $string1 = "Imminent-Monitor" 
        $string2 = "abuse@imminentmethods.net"
        $string3 = "SevenZipHelper"
        $string4 = "get_EntryPoint"
        $string5 = "WrapNonExceptionThrows"
    condition:
        uint16(0) == 0x5A4D and all of them
}
