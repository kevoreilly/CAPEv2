rule CRAT {
    meta:
        author = "ditekSHen"
        description = "CRAT payload"
        cape_type = "CRAT Payload"
    strings:
        $s1 = "cmd /c \"dir %s /s >> %s\"" wide
        $s2 = "Set-Cookie:\\b*{.+?}\\n" wide
        $s3 = "Location: {[0-9]+}" wide
        $s4 = "Content-Disposition: form-data; name=\"%s\"; filename=\"" ascii
        $s6 = "%serror.log" wide
        $v2x_1 = "?timestamp=%u" wide
        $v2x_2 = "config.txt" wide
        $v2x_3 = "entdll.dll" wide
        $v2x_4 = "\\cmd.exe" wide
        $v2x_5 = "[MyDocuments]" wide
        $v2x_6 = "@SetWindowTextW FindFileExA" wide
        $v2x_7 = "Microsoft\\Windows\\WinX\\Group1\\*.exe" wide
        $v2s_1 = "Installed Anti Virus Programs" ascii
        $v2s_2 = "Running Processes" ascii
        $v2s_3 = "id=%u&content=" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 6 of ($v2x*) or all of ($v2s*) or (2 of ($v2s*) and 4 of ($v2x*)))
}

rule CRATPluginKeylogger {
    meta:
        author = "ditekshen"
        description = "CRAT keylogger plugin payload"
        cape_type = "CRAT KeyloggerPlugin Payload"
    strings:
        $ai1 = "VM detected!" fullword wide
        $ai2 = "Sandbox detected!" fullword wide
        $ai3 = "Debug detected!" fullword wide
        $ai4 = "Analysis process detected!" fullword wide
        $s1 = "Create KeyLogMutex %s failure %d" wide
        $s2 = "Key Log Mutex already created! %s" wide
        $s3 = /KeyLogThread\s(started|finished|terminated)!/ wide
        $s4 = /KeyLog_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($ai*) and 1 of ($s*)) or (3 of ($s*) and 1 of ($ai*)) or 5 of them)
}

rule CRATPluginClipboardMonitor {
    meta:
        author = "ditekshen"
        description = "CRAT clipboard monitor plugin payload"
        cape_type = "CRAT ClipboardMonitorPlugin Payload"
    strings:
        $ai1 = "VM detected!" fullword wide
        $ai2 = "Sandbox detected!" fullword wide
        $ai3 = "Debug detected!" fullword wide
        $ai4 = "Analysis process detected!" fullword wide
        $s1 = "Clipboard Monitor Mutex [%s] already created!" wide
        $s2 = "ClipboardMonitorThread started!" fullword wide
        $s3 = /MonitorClipboardThread\s(finished|terminated)!/ wide
        $s4 = /ClipboardMonitor_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($ai*) and 1 of ($s*)) or (3 of ($s*) and 1 of ($ai*)) or 5 of them)
}

rule CRATPluginScreenCapture {
    meta:
        author = "ditekshen"
        description = "CRAT screen capture plugin payload"
        cape_type = "CRAT ScreenCapturePlugin Payload"
    strings:
        $ai1 = "VM detected!" fullword wide
        $ai2 = "Sandbox detected!" fullword wide
        $ai3 = "Debug detected!" fullword wide
        $ai4 = "Analysis process detected!" fullword wide
        $s1 = "User is inactive!, give up capture" wide
        $s2 = "Capturing screen..." wide
        $s3 = "%s\\P%02d%lu.tmp" fullword wide
        $s4 = "CloseHandle ScreenCaptureMutex failure! %d" fullword wide
        $s5 = "ScreenCaptureMutex already created! %s" fullword wide
        $s6 = "Create ScreenCaptureMutex %s failure %d" fullword wide
        $s7 = /ScreenCaptureThread\s(finished|terminated)!/ wide
        $s8 = /ScreenCapture_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($ai*) and 1 of ($s*)) or (3 of ($s*) and 1 of ($ai*)) or 6 of them)
}

rule CRATRansomHansom {
    meta:
        author = "ditekshen"
        description = "CRAT hansom ransom plugin payload"
        cape_type = "CRAT HansomRansomPlugin Payload"
    strings:
        $cmd1 = "/f /im \"%s\"" wide
        $cmd2 = "add HKLM\\%s /v %s /t REG_DWORD /d %d /F" wide
        $cmd3 = "add HKCU\\%s /v %s /t REG_DWORD /d %d /F" wide
        $cmd4 = "\"%s\" a -y -ep -k -r -s -ibck -df -m0 -hp%s -ri1:%d \"%s\" \"%s\"" wide
        $s1 = "\\hansom.jpg" wide
        $s2 = "HansomMain" fullword ascii wide
        $s3 = "ExtractHansom" fullword ascii wide
        $s4 = "Hansom2008" fullword ascii
        $s5 = ".hansomkey" fullword wide
        $s6 = ".hansom" fullword wide
        $s7 = /Ransom_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((2 of ($cmd*) and 2 of ($s*)) or (4 of ($s*) and 1 of ($cmd*)) or 6 of them)
}
