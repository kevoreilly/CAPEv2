rule WSHRAT {
    meta:
        author = "ditekshen"
        description = "WSHRAT keylogger plugin payload"
        cape_type = "WSHRAT payload"
    strings:
        $s1 = "GET /open-keylogger HTTP/1.1" fullword wide
        $s2 = "KeyboardChange: nCode={0}, wParam={1}, vkCode={2}, scanCode={3}, flags={4}, dwExtraInfo={6}" wide
        $s3 = "MouseChange: nCode={0}, wParam={1}, x={2}, y={3}, mouseData={4}, flags={5}, dwExtraInfo={7}" wide
        $s4 = "sendKeyLog" fullword ascii
        $s5 = "saveKeyLog" fullword ascii
        $s6 = "get_TotalKeyboardClick" fullword ascii
        $s7 = "get_SessionMouseClick" fullword ascii
        $pdb = "\\Android\\documents\\visual studio 2010\\Projects\\Keylogger\\Keylogger\\obj\\x86\\Debug\\Keylogger.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 4 of them
}
