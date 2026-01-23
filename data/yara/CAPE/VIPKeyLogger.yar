rule VIPKeyLogger
{
    meta:
        author = "kevoreilly"
        description = "Detects VIPKeyLogger Keylogger"
        cape_type = "VIPKeyLogger Payload"
        packed = "edaba79c3d43a416a86003f336d879ed3a513aa24dd401340584615647ed6da2"
    strings:
        $s1 = "/ VIP Recovery \\"  wide
        $s2 = "Clipboard Logs ID"  wide
        $s3 = "Keylogger" wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
