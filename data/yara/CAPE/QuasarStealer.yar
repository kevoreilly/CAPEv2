rule QuasarStealer {
    meta:
        author = "ditekshen"
        description = "Detects Quasar infostealer"
        cape_type = "QuasarStealer Payload"
    strings:
        $s1 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null" fullword ascii
        $s2 = "DQuasar.Common, Version=1.4.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii
        $s3 = "Process already elevated." fullword wide
        $s4 = "get_PotentiallyVulnerablePasswords" fullword ascii
        $s5 = "GetKeyloggerLogsDirectory" ascii
        $s6 = "set_PotentiallyVulnerablePasswords" fullword ascii
        $s7 = "BQuasar.Client.Extensions.RegistryKeyExtensions+<GetKeyValues>" ascii
    condition:
      uint16(0) == 0x5a4d and 5 of them
}
