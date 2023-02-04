rule OrcusRAT {
    meta:
        author = "ditekshen"
        description = "OrcusRAT RAT payload"
        cape_type = "OrcusRAT payload"
    strings:
        $s1 = "Orcus.Shared.Commands.Password.RecoveredPassword" ascii
        $s2 = "Orcus.Commands.DeviceManager.HardwareHelper.TemporaryDeviceInfo" ascii
        $s3 = "Orcus.Shared.Commands.LiveKeylogger" ascii
        $s4 = "Orcus.Shared.Commands.Keylogger" ascii
        $s5 = "Orcus.Shared.Commands.DropAndExecute" ascii
        $s6 = "Orcus.Commands.DropAndExecute" ascii
        $s7 = "Orcus.Commands.Passwords.Applications." ascii
        $s8 = "Orcus.Shared.Commands.WindowManager" ascii
        $s9 = "Orcus.Shared.Commands.AudioVolumeControl" ascii
        $bytes = { e8 e9 e6 bb b8 cb be b0 83 92 97 da 98 c7 fa a7
                   a4 d7 aa a7 9c 8c 81 9a 93 90 62 4b 7e 64 7c 6e
                   2d 6d 06 4a 6b 7f 6b 6f 6c 60 31 2b 32 2d 3a 33
                   7b 76 7b 67 75 61 7b 71 7c 74 07 2f 2c 2d 2a 55
                   65 61 5c 27 24 25 22 6b 61 73 7a 68 7d 6f 7f 67
                   7c 7c 65 74 66 7c 62 67 79 7e 00 13 1f 34 39 3f
                   2d 24 1a 04 21 2b 36 31 21 2d 0e 2d 33 3e 3f 28
                   2b 36 24 0b 64 55 52 62 60 61 58 5d 5e 6d 6a 37
                   03 2c 34 09 21 29 51 51 4e 25 32 13 7c 7d 7a 55
                   1b 1f 11 77 74 75 72 17 35 1d cb fb c9 eb e6 }
    condition:
        uint16(0) == 0x5a4d and (1 of ($s*) or $bytes)
}
