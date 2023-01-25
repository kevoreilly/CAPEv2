rule CobaltStrikeBeacon
{
    meta:
        author = "ditekshen, enzo & Elastic"
        description = "Cobalt Strike Beacon Payload"
        cape_type = "CobaltStrikeBeacon Payload"
    strings:
        $s1 = "%%IMPORT%%" fullword ascii
        $s2 = "www6.%x%x.%s" fullword ascii
        $s3 = "cdn.%x%x.%s" fullword ascii
        $s4 = "api.%x%x.%s" fullword ascii
        $s5 = "%s (admin)" fullword ascii
        $s6 = "could not spawn %s: %d" fullword ascii
        $s7 = "Could not kill %d: %d" fullword ascii
        $s8 = "Could not connect to pipe (%s): %d" fullword ascii
        $s9 = /%s\.\d[(%08x).]+\.%x%x\.%s/ ascii
        $pwsh1 = "IEX (New-Object Net.Webclient).DownloadString('http" ascii
        $pwsh2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
        $ver3a = {69 68 69 68 69 6b ?? ?? 69}
        $ver3b = {69 69 69 69}
        $ver4a = {2e 2f 2e 2f 2e 2c ?? ?? 2e}
        $ver4b = {2e 2e 2e 2e}
        $a1 = "%02d/%02d/%02d %02d:%02d:%02d" xor(0x00-0xff)
        $a2 = "Started service %s on %s" xor(0x00-0xff)
        $a3 = "%s as %s\\%s: %d" xor(0x00-0xff)
        $b_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
        $b_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}
    condition:
        all of ($ver3*) or all of ($ver4*) or 2 of ($a*) or any of ($b*) or 5 of ($s*) or (all of ($pwsh*) and 2 of ($s*)) or (#s9 > 6 and 4 of them)
}
