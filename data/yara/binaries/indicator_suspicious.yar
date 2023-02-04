import "pe"

rule INDICATOR_SUSPICIOUS_GENRansomware {
    meta:
        description = "detects command variations typically used by ransomware"
        author = "ditekSHen"
    strings:
        $cmd1 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii wide nocase
        $cmd2 = "vssadmin.exe Delete Shadows /all" ascii wide nocase
        $cmd3 = "Delete Shadows /all" ascii wide nocase
        $cmd4 = "} recoveryenabled no" ascii wide nocase
        $cmd5 = "} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd6 = "wmic SHADOWCOPY DELETE" ascii wide nocase
        $cmd7 = "\\Microsoft\\Windows\\SystemRestore\\SR\" /disable" ascii wide nocase
        $cmd8 = "resize shadowstorage /for=c: /on=c: /maxsize=" ascii wide nocase
        $cmd9 = "shadowcopy where \"ID='%s'\" delete" ascii wide nocase
        $cmd10 = "wmic.exe SHADOWCOPY /nointeractive" ascii wide nocase
        $cmd11 = "WMIC.exe shadowcopy delete" ascii wide nocase
        $cmd12 = "Win32_Shadowcopy | ForEach-Object {$_.Delete();}" ascii wide nocase
        $delr = /del \/s \/f \/q(( [A-Za-z]:\\(\*\.|[Bb]ackup))(VHD|bac|bak|wbcat|bkf)?)+/ ascii wide
        $wp1 = "delete catalog -quiet" ascii wide nocase
        $wp2 = "wbadmin delete backup" ascii wide nocase
        $wp3 = "delete systemstatebackup" ascii wide nocase
    condition:
        (uint16(0) == 0x5a4d and 2 of ($cmd*) or (1 of ($cmd*) and 1 of ($wp*)) or #delr > 4) or (4 of them)
}

rule INDICATOR_SUSPICIOUS_ReflectiveLoader {
    meta:
        description = "detects Reflective DLL injection artifacts"
        author = "ditekSHen"
    strings:
        $s1 = "_ReflectiveLoader@" ascii wide
        $s2 = "ReflectiveLoader@" ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of them or (
            pe.exports("ReflectiveLoader@4") or
            pe.exports("_ReflectiveLoader@4") or
            pe.exports("ReflectiveLoader")
            )
        )
}

rule INDICATOR_SUSPICIOUS_IMG_Embedded_Archive {
    meta:
        description = "Detects images embedding archives. Observed in TheRat RAT."
        author = "@ditekSHen"
    strings:
        $sevenzip1 = { 37 7a bc af 27 1c 00 04 } // 7ZIP, regardless of password-protection
        $sevenzip2 = { 37 e4 53 96 c9 db d6 07 } // 7ZIP zisofs compression format
        $zipwopass = { 50 4b 03 04 14 00 00 00 } // None password-protected PKZIP
        $zipwipass = { 50 4b 03 04 33 00 01 00 } // Password-protected PKZIP
        $zippkfile = { 50 4b 03 04 0a 00 02 00 } // PKZIP
        $rarheade1 = { 52 61 72 21 1a 07 01 00 } // RARv4
        $rarheade2 = { 52 65 74 75 72 6e 2d 50 } // RARv5
        $rarheade3 = { 52 61 72 21 1a 07 00 cf } // RAR
        $mscabinet = { 4d 53 46 54 02 00 01 00 } // Microsoft cabinet file
        $zlockproe = { 50 4b 03 04 14 00 01 00 } // ZLock Pro encrypted ZIP
        $winzip    = { 57 69 6E 5A 69 70 }       // WinZip compressed archive
        $pklite    = { 50 4B 4C 49 54 45 }       // PKLITE compressed ZIP archive
        $pksfx     = { 50 4B 53 70 58 }          // PKSFX self-extracting executable compressed file
    condition:
        // JPEG or JFIF or PNG or BMP
        (uint32(0) == 0xe0ffd8ff or uint32(0) == 0x474e5089 or uint16(0) == 0x4d42) and 1 of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_EventViewer {
    meta:
        description = "detects Windows exceutables potentially bypassing UAC using eventvwr.exe"
        author = "ditekSHen"
    strings:
        $s1 = "\\Classes\\mscfile\\shell\\open\\command" ascii wide nocase
        $s2 = "eventvwr.exe" ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CleanMgr {
    meta:
        description = "detects Windows exceutables potentially bypassing UAC using cleanmgr.exe"
        author = "ditekSHen"
    strings:
        $s1 = "\\Enviroment\\windir" ascii wide nocase
        $s2 = "\\system32\\cleanmgr.exe" ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_Enable_OfficeMacro {
    meta:
        description = "Detects Windows executables referencing Office macro registry keys. Observed modifying Office configurations via the registy to enable macros"
        author = "@ditekSHen"
    strings:
        $s1 = "\\Word\\Security\\VBAWarnings" ascii wide
        $s2 = "\\PowerPoint\\Security\\VBAWarnings" ascii wide
        $s3 = "\\Excel\\Security\\VBAWarnings" ascii wide

        $h1 = "5c576f72645c53656375726974795c5642415761726e696e6773" nocase ascii wide
        $h2 = "5c506f776572506f696e745c53656375726974795c5642415761726e696e6773" nocase ascii wide
        $h3 = "5c5c457863656c5c5c53656375726974795c5c5642415761726e696e6773" nocase ascii wide

        $d1 = "5c%57%6f%72%64%5c%53%65%63%75%72%69%74%79%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
        $d2 = "5c%50%6f%77%65%72%50%6f%69%6e%74%5c%53%65%63%75%72%69%74%79%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
        $d3 = "5c%5c%45%78%63%65%6c%5c%5c%53%65%63%75%72%69%74%79%5c%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or 2 of ($h*) or 2 of ($d*))
}

rule INDICATOR_SUSPICIOUS_EXE_Disable_OfficeProtectedView {
    meta:
        description = "Detects Windows executables referencing Office ProtectedView registry keys. Observed modifying Office configurations via the registy to disable ProtectedView"
        author = "@ditekSHen"
    strings:
        $s1 = "\\Security\\ProtectedView\\DisableInternetFilesInPV" ascii wide
        $s2 = "\\Security\\ProtectedView\\DisableAttachementsInPV" ascii wide
        $s3 = "\\Security\\ProtectedView\\DisableUnsafeLocationsInPV" ascii wide

        $h1 = "5c53656375726974795c50726f746563746564566965775c44697361626c65496e7465726e657446696c6573496e5056" nocase ascii wide
        $h2 = "5c53656375726974795c50726f746563746564566965775c44697361626c65417474616368656d656e7473496e5056" nocase ascii wide
        $h3 = "5c53656375726974795c50726f746563746564566965775c44697361626c65556e736166654c6f636174696f6e73496e5056" nocase ascii wide

        $d1 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%49%6e%74%65%72%6e%65%74%46%69%6c%65%73%49%6e%50%56" nocase ascii
        $d2 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%41%74%74%61%63%68%65%6d%65%6e%74%73%49%6e%50%56" nocase ascii
        $d3 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%55%6e%73%61%66%65%4c%6f%63%61%74%69%6f%6e%73%49%6e%50%56" nocase ascii
    condition:
         uint16(0) == 0x5a4d and (2 of ($s*) or 2 of ($h*) or 2 of ($d*))
}

rule INDICATOR_SUSPICIOUS_EXE_SandboxProductID {
    meta:
        description = "Detects binaries and memory artifcats referencing sandbox product IDs"
        author = "ditekSHen"
    strings:
        $id1 = "76487-337-8429955-22614" fullword ascii wide // Anubis Sandbox
        $id2 = "76487-644-3177037-23510" fullword ascii wide // CW Sandbox
        $id3 = "55274-640-2673064-23950" fullword ascii wide // Joe Sandbox
        $id4 = "76487-640-1457236-23837" fullword ascii wide // Anubis Sandbox
        $id5 = "76497-640-6308873-23835" fullword ascii wide // CWSandbox
        $id6 = "76487-640-1464517-23259" fullword ascii wide // ??
        $id7 = "76487 - 337 - 8429955 - 22614" fullword ascii wide // Anubis Sandbox
        $id8 = "76487 - 644 - 3177037 - 23510" fullword ascii wide // CW Sandbox
        $id9 = "55274 - 640 - 2673064 - 23950" fullword ascii wide // Joe Sandbox
        $id10 = "76487 - 640 - 1457236 - 23837" fullword ascii wide // Anubis Sandbox
        $id11 = "76497 - 640 - 6308873 - 23835" fullword ascii wide // CWSandbox
        $id12 = "76487 - 640 - 1464517 - 23259" fullword ascii wide // ??
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_SUSPICIOUS_EXE_SandboxHookingDLL {
    meta:
        description = "Detects binaries and memory artifcats referencing sandbox DLLs typically observed in sandbox evasion"
        author = "ditekSHen"
    strings:
        $dll1 = "sbiedll.dll" nocase fullword ascii wide
        // $dll2 = "dbghelp.dll" nocase fullword ascii wide
        $dll3 = "api_log.dll" nocase fullword ascii wide
        $dll4 = "pstorec.dll" nocase fullword ascii wide
        $dll5 = "dir_watch.dll" nocase fullword ascii wide
        $dll6 = "vmcheck.dll" nocase fullword ascii wide
        $dll7 = "wpespy.dll" nocase fullword ascii wide
        $dll8 = "SxIn.dll" nocase fullword ascii wide
        $dll9 = "Sf2.dll" nocase fullword ascii wide
        $dll10 = "deploy.dll" nocase fullword ascii wide
        $dll11 = "avcuf32.dll" nocase fullword ascii wide
        $dll12 = "BgAgent.dll" nocase fullword ascii wide
        $dll13 = "guard32.dll" nocase fullword ascii wide
        $dll14 = "wl_hook.dll" nocase fullword ascii wide
        $dll15 = "QOEHook.dll" nocase fullword ascii wide
        $dll16 = "a2hooks32.dll" nocase fullword ascii wide
        $dll17 = "tracer.dll" nocase fullword ascii wide
        $dll18 = "APIOverride.dll" nocase fullword ascii wide
        $dll19 = "NtHookEngine.dll" nocase fullword ascii wide
        $dll20 = "LOG_API.DLL" nocase fullword ascii wide
        $dll21 = "LOG_API32.DLL" nocase fullword ascii wide
        $dll22 = "vmcheck32.dll" nocase ascii wide
        $dll23 = "vmcheck64.dll" nocase ascii wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_AHK_Downloader {
    meta:
        description = "Detects AutoHotKey binaries acting as second stage droppers"
        author = "ditekSHen"
    strings:
        $d1 = "URLDownloadToFile, http" ascii
        $d2 = "URLDownloadToFile, file" ascii
        $s1 = ">AUTOHOTKEY SCRIPT<" fullword wide
        $s2 = "open \"%s\" alias AHK_PlayMe" fullword wide
        $s3 = /AHK\s(Keybd|Mouse)/ fullword wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($d*) and 1 of ($s*))
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCOM {
    meta:
        description = "Detects Windows exceutables bypassing UAC using CMSTP COM interfaces. MITRE (T1218.003)"
        author = "ditekSHen"
    strings:
        // CMSTPLUA
        $guid1 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide nocase
        // CMLUAUTIL
        $guid2 = "{3E000D72-A845-4CD9-BD83-80C07C3B881F}" ascii wide nocase
        // Connection Manager LUA Host Object
        $guid3 = "{BA126F01-2166-11D1-B1D0-00805FC1270E}" ascii wide nocase
        $s1 = "CoGetObject" fullword ascii wide
        $s2 = "Elevation:Administrator!new:" fullword ascii wide
    condition:
       uint16(0) == 0x5a4d and (1 of ($guid*) and 1 of ($s*))
}

rule INDICATOR_SUSPICIOUS_ClearWinLogs {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing commands for clearing Windows Event Logs"
    strings:
        $cmd1 = "wevtutil.exe clear-log" ascii wide nocase
        $cmd2 = "wevtutil.exe cl " ascii wide nocase
        $cmd3 = ".ClearEventLog()" ascii wide nocase
        $cmd4 = "Foreach-Object {wevtutil cl \"$_\"}" ascii wide nocase
        $cmd5 = "('wevtutil.exe el') DO (call :do_clear" ascii wide nocase
        $cmd6 = "| ForEach { Clear-EventLog $_.Log }" ascii wide nocase
        $cmd7 = "('wevtutil.exe el') DO wevtutil.exe cl \"%s\"" ascii wide nocase
        $t1 = "wevtutil" ascii wide nocase
        $l1 = "cl Application" ascii wide nocase
        $l2 = "cl System" ascii wide nocase
        $l3 = "cl Setup" ascii wide nocase
        $l4 = "cl Security" ascii wide nocase
        $l5 = "sl Security /e:false" ascii wide nocase
        $ne1 = "wevtutil.exe cl Aplicaci" fullword wide
        $ne2 = "wevtutil.exe cl Application /bu:C:\\admin\\backup\\al0306.evtx" fullword wide
        $ne3 = "wevtutil.exe cl Application /bu:C:\\admin\\backups\\al0306.evtx" fullword wide
    condition:
        uint16(0) == 0x5a4d and not any of ($ne*) and ((1 of ($cmd*)) or (1 of ($t*) and 4 of ($l*)))
}

rule INDICATOR_SUSPICIOUS_DisableWinDefender {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing artifcats associated with disabling Widnows Defender"
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
        $reg2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
        $s1 = "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true" ascii wide nocase
        $s2 = "Set-MpPreference -DisableArchiveScanning $true" ascii wide nocase
        $s3 = "Set-MpPreference -DisableIntrusionPreventionSystem $true" ascii wide nocase
        $s4 = "Set-MpPreference -DisableScriptScanning $true" ascii wide nocase
        $s5 = "Set-MpPreference -SubmitSamplesConsent 2" ascii wide nocase
        $s6 = "Set-MpPreference -MAPSReporting 0" ascii wide nocase
        $s7 = "Set-MpPreference -HighThreatDefaultAction 6" ascii wide nocase
        $s8 = "Set-MpPreference -ModerateThreatDefaultAction 6" ascii wide nocase
        $s9 = "Set-MpPreference -LowThreatDefaultAction 6" ascii wide nocase
        $s10 = "Set-MpPreference -SevereThreatDefaultAction 6" ascii wide nocase
        $s11 = "Set-MpPreference -EnableControlledFolderAccess Disabled" ascii wide nocase
        $pdb = "\\Disable-Windows-Defender\\obj\\Debug\\Disable-Windows-Defender.pdb" ascii
        $e1 = "Microsoft\\Windows Defender\\Exclusions\\Paths" ascii wide nocase
        $e2 = "Add-MpPreference -Exclusion" ascii wide nocase
        $c1 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($reg*) and 1 of ($s*)) or ($pdb) or all of ($e*) or #c1 > 1)
}

rule INDICATOR_SUSPICIOUS_USNDeleteJournal {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing anti-forensic artifcats of deletiing USN change journal. Observed in ransomware"
    strings:
        $cmd1 = "fsutil.exe" ascii wide nocase
        $s1 = "usn deletejournal /D C:" ascii wide nocase
        $s2 = "fsutil.exe usn deletejournal" ascii wide nocase
        $s3 = "fsutil usn deletejournal" ascii wide nocase
        $ne1 = "fsutil usn readdata C:\\Temp\\sample.txt" wide
        $ne2 = "fsutil transaction query {0f2d8905-6153-449a-8e03-7d3a38187ba1}" wide
        $ne3 = "fsutil resource start d:\\foobar d:\\foobar\\LogDir\\LogBLF::TxfLog d:\\foobar\\LogDir\\LogBLF::TmLog" wide
        $ne4 = "fsutil objectid query C:\\Temp\\sample.txt" wide
    condition:
        uint16(0) == 0x5a4d and (not any of ($ne*) and (1 of ($cmd*) and 1 of ($s*)))
}

rule INDICATOR_SUSPICIOUS_WMIC_Downloader {
    meta:
        author = "ditekSHen"
        description = "Detects files utilizing WMIC for whitelisting bypass and downloading second stage payloads"
    strings:
        $s1 = "WMIC.exe os get /format:\"http" wide
        $s2 = "WMIC.exe computersystem get /format:\"http" wide
        $s3 = "WMIC.exe dcomapp get /format:\"http" wide
        $s4 = "WMIC.exe desktop get /format:\"http" wide
    condition:
        (uint16(0) == 0x004c or uint16(0) == 0x5a4d) and 1 of them
}

rule INDICATOR_SUSPICIOUS_PE_ResourceTuner {
    meta:
        author = "ditekSHen"
        description = "Detects executables with modified PE resources usning the unpaid version of Resource Tuner"
    strings:
        $s1 = "Modified by an unpaid evaluation copy of Resource Tuner 2 (www.heaventools.com)" fullword wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_ASEP_REG_Reverse {
    meta:
        author = "ditekSHen"
        description = "Detects file containing reversed ASEP Autorun registry keys"
    strings:
        $s1 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s2 = "ecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s3 = "secivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s4 = "xEecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s5 = "ecnOsecivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s6 = "yfitoN\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s7 = "tiniresU\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s8 = "nuR\\rerolpxE\\seiciloP\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s9 = "stnenopmoC dellatsnI\\puteS evitcA\\tfosorciM" ascii wide nocase
        $s10 = "sLLD_tinIppA\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s11 = "snoitpO noitucexE eliF egamI\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s12 = "llehS\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s13 = "daol\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s14 = "daoLyaleDtcejbOecivreSllehS\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s15 = "nuRotuA\\rossecorP\\dnammoC\\tfosorciM" ascii wide nocase
        $s16 = "putratS\\sredloF llehS resU\\rerolpxE\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s17 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\teSlortnoCtnerruC\\metsyS" ascii wide nocase
        $s18 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\100teSlortnoC\\metsyS" ascii wide nocase
        $s19 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\erawtfoS" ascii wide nocase
        $s20 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\edoN2346woW\\erawtfoS" ascii wide nocase
    condition:
        1 of them and filesize < 2000KB
}

rule INDICATOR_SUSPICIOUS_EXE_SQLQuery_ConfidentialDataStore {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing SQL queries to confidential data stores. Observed in infostealers"
    strings:
        $select = "select " ascii wide nocase
        $table1 = " from credit_cards" ascii wide nocase
        $table2 = " from logins" ascii wide nocase
        $table3 = " from cookies" ascii wide nocase
        $table4 = " from moz_cookies" ascii wide nocase
        $table5 = " from moz_formhistory" ascii wide nocase
        $table6 = " from moz_logins" ascii wide nocase
        $column1 = "name" ascii wide nocase
        $column2 = "password_value" ascii wide nocase
        $column3 = "encrypted_value" ascii wide nocase
        $column4 = "card_number_encrypted" ascii wide nocase
        $column5 = "isHttpOnly" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 2 of ($table*) and 2 of ($column*) and $select
}

rule INDICATOR_SUSPICIOUS_PWSH_B64Encoded_Concatenated_FileEXEC {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell scripts containing patterns of base64 encoded files, concatenation and execution"
    strings:
        $b1 = "::WriteAllBytes(" ascii
        $b2 = "::FromBase64String(" ascii
        $b3 = "::UTF8.GetString(" ascii

        $s1 = "-join" nocase ascii
        $s2 = "[Char]$_"
        $s3 = "reverse" nocase ascii
        $s4 = " += " ascii

        $e1 = "System.Diagnostics.Process" ascii
        $e2 = /StartInfo\.(Filename|UseShellExecute)/ ascii
        $e3 = /-eq\s'\.(exe|dll)'\)/ ascii
        $e4 = /(Get|Start)-(Process|WmiObject)/ ascii
    condition:
        #s4 > 10 and ((3 of ($b*)) or (1 of ($b*) and 2 of ($s*) and 1 of ($e*)) or (8 of them))
}

rule INDICATOR_SUSPICIOUS_JS_Hex_B64Encoded_EXE {
    meta:
        author = "ditekSHen"
        description = "Detects JavaScript files hex and base64 encoded executables"
    strings:
        $s1 = ".SaveToFile" ascii
        $s2 = ".Run" ascii
        $s3 = "ActiveXObject" ascii
        $s4 = "fromCharCode" ascii
        $s5 = "\\x66\\x72\\x6F\\x6D\\x43\\x68\\x61\\x72\\x43\\x6F\\x64\\x65" ascii
        $binary = "\\x54\\x56\\x71\\x51\\x41\\x41" ascii
        $pattern = /[\s\{\(\[=]_0x[0-9a-z]{3,6}/ ascii
    condition:
        $binary and $pattern and 2 of ($s*) and filesize < 2500KB
}

rule INDICATOR_SUSPICIOUS_EXE_PWSH_Downloader {
    meta:
        author = "ditekSHen"
        description = "Detects downloader agent, using PowerShell"
    strings:
        $pwsh = "powershell" fullword ascii
        $bitstansfer = "Start-BitsTransfer" ascii wide
        $s1 = "GET %s HTTP/1" ascii
        $s2 = "User-Agent:" ascii
        $s3 = "-WindowStyle Hidden -ep bypass -file \"" fullword ascii
        $s4 = "LdrLoadDll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and $pwsh and ($bitstansfer or 2 of ($s*))
}

rule INDICATOR_SUSPICIOUS_PWSH_PasswordCredential_RetrievePassword {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell content designed to retrieve passwords from host"
    strings:
        $namespace = "Windows.Security.Credentials.PasswordVault" ascii wide nocase
        $method1 = "RetrieveAll()" ascii wide nocase
        $method2 = ".RetrievePassword()" ascii wide nocase
    condition:
       $namespace and 1 of ($method*)
}

rule INDICATOR_SUSPICIOUS_UACBypass_EnvVarScheduledTasks {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC (ab)using Environment Variables in Scheduled Tasks"
    strings:
        $s1 = "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" ascii wide
        $s2 = "\\Environment" ascii wide
        $s3 = "schtasks" ascii wide
        $s4 = "/v windir" ascii wide
    condition:
       all of them
}

rule INDICATOR_SUSPICIOUS_UACBypass_fodhelper {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC using fodhelper.exe"
    strings:
        $s1 = "\\software\\classes\\ms-settings\\shell\\open\\command" ascii wide nocase
        $s2 = "DelegateExecute" ascii wide
        $s3 = "fodhelper" ascii wide
        $s4 = "ConsentPromptBehaviorAdmin" ascii wide
    condition:
       all of them
}

rule INDICATOR_SUSPICIOUS_Win_GENERIC01 {
    meta:
        author = "ditekSHen"
        description = "Detects known unamed malicious executables, mostly DLLs"
    strings:
        $s1 = "xcopy \"%s\" \"%s\" /e /i /y" fullword ascii
        $s2 = "LoadFromMemory END---" fullword ascii
        $s3 = "<<== Message sending:" fullword ascii
        $s4 = "==>> Message received:" fullword ascii
        $s5 = "I am virus! Fuck you" ascii
        $s6 = "TMBMSRV.exe" fullword ascii
        $s7 = "rtvscan.exe" fullword ascii
        $s8 = "SPIDer.exe" fullword ascii
        $s9 = "kxetray.exe" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_SUSPICIOUS_Win_GENERIC02 {
    meta:
        author = "ditekSHen"
        description = "Detects known unamed malicious executables, mostly DLLs"
    strings:
        $s1 = "\\wmkawe_%d.data" ascii
        $s2 = "\\resmon.resmoncfg" ascii
        $s3 = "ByPassUAC" fullword ascii
        $s4 = "rundll32.exe C:\\ProgramData\\Sandboxie\\SbieMsg.dll,installsvc" fullword ascii nocase
        $s5 = "%s\\SbieMsg." ascii
        $s6 = "Stupid Japanese" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_SUSPICIOUS_Win_GENERIC03 {
    meta:
        author = "ditekSHen"
        description = "Detects known unamed malicious executables"
    strings:
        $s1 = "{%s-%d-%d}" fullword wide
        $s2 = "update" fullword wide
        $s3 = "https://" fullword wide
        $s4 = "http://" fullword wide
        $s5 = "configure" fullword ascii
        $s6 = { 8d 4f 02 e8 8c ff ff ff 8b d8 81 fb 00 dc 00 00 }
        $s7 = { 83 c1 02 e8 3c ff ff ff 8b c8 ba ff 03 00 00 8d }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_Finger_Download_Pattern {
    meta:
        author = "ditekSHen"
        description = "Detects files embedding and abusing the finger command for download"
    strings:
        $pat1 = /finger(\.exe)?\s.{1,50}@.{7,10}\|/ ascii wide
        $pat2 = "-Command \"finger" ascii wide
        $ne1 = "Nmap service detection probe list" ascii
    condition:
       not any of ($ne*) and any of ($pat*)
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCMD {
    meta:
        author = "ditekSHen"
        description = "Detects Windows exceutables bypassing UAC using CMSTP utility, command line and INF"
    strings:
        $s1 = "c:\\windows\\system32\\cmstp.exe" ascii wide nocase
        $s2 = "taskkill /IM cmstp.exe /F" ascii wide nocase
        $s3 = "CMSTPBypass" fullword ascii
        $s4 = "CommandToExecute" fullword ascii
        $s5 = "RunPreSetupCommands=RunPreSetupCommandsSection" fullword wide
        $s6 = "\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%UnexpectedError%\", \"\"" fullword wide nocase
    condition:
       uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_JS_WMI_ExecQuery {
    meta:
        author = "ditekSHen"
        description = "Detects JS potentially executing WMI queries"
    strings:
        $ex = ".ExecQuery(" ascii nocase
        $s1 = "GetObject(" ascii nocase
        $s2 = "String.fromCharCode(" ascii nocase
        $s3 = "ActiveXObject(" ascii nocase
        $s4 = ".Sleep(" ascii nocase
    condition:
       ($ex and 2 of ($s*))
}

rule INDICATOR_SUSPICIOUS_PWSHLoader_RunPE {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell PE loader / executer. Observed MasterMana TTPs"
    strings:
        $rp1 = "GetType('RunPe.RunPe'" ascii
        $rp2 = "GetType(\"RunPe.RunPe\"" ascii
        $rm1 = "GetMethod('Run'" ascii
        $rm2 = "GetMethod(\"Run\"" ascii
        $s1 = ".Invoke(" ascii
        $s2 = "[Reflection.Assembly]::Load(" ascii
    condition:
        all of ($s*) and 1 of ($rp*) and 1 of ($rm*)
}

rule INDICATOR_SUSPICIOUS_PELoader_RunPE {
    meta:
        author = "ditekSHen"
        description = "Detects PE loader / injector. Observed Gorgon TTPs"
    strings:
        $s1 = "commandLine'" fullword ascii
        $s2 = "RunPe.dll" fullword ascii
        $s3 = "HandleRun" fullword ascii
        $s4 = "inheritHandles" fullword ascii
        $s5 = "BlockCopy" fullword ascii
        $s6 = "WriteProcessMemory" fullword ascii
        $s7 = "startupInfo" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule INDICATOR_SUSPICIOUS_XML_Liverpool_Downlaoder_UserConfig {
    meta:
        author = "ditekSHen"
        description = "Detects XML files associated with 'Liverpool' downloader containing encoded executables"
    strings:
        $s1 = "<configSections>" ascii nocase
        $s2 = "<value>77 90" ascii nocase
    condition:
       uint32(0) == 0x6d783f3c and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_SandboxUserNames {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing possible sandbox analysis VM usernames"
    strings:
        $s1 = "15pb" fullword ascii wide nocase
        $s2 = "7man2" fullword ascii wide nocase
        $s3 = "stella" fullword ascii wide nocase
        $s4 = "f4kh9od" fullword ascii wide nocase
        $s5 = "willcarter" fullword ascii wide nocase
        $s6 = "biluta" fullword ascii wide nocase
        $s7 = "ehwalker" fullword ascii wide nocase
        $s8 = "hong lee" fullword ascii wide nocase
        $s9 = "joe cage" fullword ascii wide nocase
        $s10 = "jonathan" fullword ascii wide nocase
        $s11 = "kindsight" fullword ascii wide nocase
        $s12 = "malware" fullword ascii wide nocase
        $s13 = "peter miller" fullword ascii wide nocase
        $s14 = "petermiller" fullword ascii wide nocase
        $s15 = "phil" fullword ascii wide nocase
        $s16 = "rapit" fullword ascii wide nocase
        $s17 = "r0b0t" fullword ascii wide nocase
        $s18 = "cuckoo" fullword ascii wide nocase
        $s19 = "vm-pc" fullword ascii wide nocase
        $s20 = "analyze" fullword ascii wide nocase
        $s21 = "roslyn" fullword ascii wide nocase
        $s22 = "vince" fullword ascii wide nocase
        $s23 = "test" fullword ascii wide nocase
        $s24 = "sample" fullword ascii wide nocase
        $s25 = "mcafee" fullword ascii wide nocase
        $s26 = "vmscan" fullword ascii wide nocase
        $s27 = "mallab" fullword ascii wide nocase
        $s28 = "abby" fullword ascii wide nocase
        $s29 = "elvis" fullword ascii wide nocase
        $s30 = "wilbert" fullword ascii wide nocase
        $s31 = "joe smith" fullword ascii wide nocase
        $s32 = "hanspeter" fullword ascii wide nocase
        $s33 = "johnson" fullword ascii wide nocase
        $s34 = "placehole" fullword ascii wide nocase
        $s35 = "tequila" fullword ascii wide nocase
        $s36 = "paggy sue" fullword ascii wide nocase
        $s37 = "klone" fullword ascii wide nocase
        $s38 = "oliver" fullword ascii wide nocase
        $s39 = "stevens" fullword ascii wide nocase
        $s40 = "ieuser" fullword ascii wide nocase
        $s41 = "virlab" fullword ascii wide nocase
        $s42 = "beginer" fullword ascii wide nocase
        $s43 = "beginner" fullword ascii wide nocase
        $s44 = "markos" fullword ascii wide nocase
        $s45 = "semims" fullword ascii wide nocase
        $s46 = "gregory" fullword ascii wide nocase
        $s47 = "tom-pc" fullword ascii wide nocase
        $s48 = "will carter" fullword ascii wide nocase
        $s49 = "angelica" fullword ascii wide nocase
        $s50 = "eric johns" fullword ascii wide nocase
        $s51 = "john ca" fullword ascii wide nocase
        $s52 = "lebron james" fullword ascii wide nocase
        $s53 = "rats-pc" fullword ascii wide nocase
        $s54 = "robot" fullword ascii wide nocase
        $s55 = "serena" fullword ascii wide nocase
        $s56 = "sofynia" fullword ascii wide nocase
        $s57 = "straz" fullword ascii wide nocase
        $s58 = "bea-ch" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 10 of them
}

rule INDICATOR_SUSPICIOUS_B64_Encoded_UserAgent {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing base64 encoded User Agent"
    strings:
        $s1 = "TW96aWxsYS81LjAgK" ascii wide
        $s2 = "TW96aWxsYS81LjAgKFdpbmRvd3M" ascii wide
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule INDICATOR_SUSPICIOUS_WindDefender_AntiEmaulation {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing potential Windows Defender anti-emulation checks"
    strings:
        $s1 = "JohnDoe" fullword ascii wide
        $s2 = "HAL9TH" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_ClearMyTracksByProcess {
    meta:
        author = "ditekSHen"
        description = "Detects executables calling ClearMyTracksByProcess"
    strings:
        $s1 = "InetCpl.cpl,ClearMyTracksByProcess" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule INDICATOR_SUSPICOIUS_EXE_TelegramChatBot {
    meta:
        author = "ditekSHen"
        description = "Detects executables using Telegram Chat Bot"
    strings:
        $s1 = "https://api.telegram.org/bot" ascii wide
        $s2 = "/sendMessage?chat_id=" fullword ascii wide
        $s3 = "Content-Disposition: form-data; name=\"" fullword ascii
        $s4 = "/sendDocument?chat_id=" fullword ascii wide
        $p1 = "/sendMessage" ascii wide
        $p2 = "/sendDocument" ascii wide
        $p3 = "&chat_id=" ascii wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or (2 of ($p*) and 1 of ($s*)))
}

rule INDICATOR_SUSPICIOUS_EXE_B64_Artifacts {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding bas64-encoded APIs, command lines, registry keys, etc."
    strings:
        $s1 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA" ascii wide
        $s2 = "L2Mgc2NodGFza3MgL2" ascii wide
        $s3 = "QW1zaVNjYW5CdWZmZXI" ascii wide
        $s4 = "VmlydHVhbFByb3RlY3Q" ascii wide
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_SUSPICIOUS_EXE_DiscordURL {
    meta:
        author = "ditekSHen"
        description = "Detects executables Discord URL observed in first stage droppers"
    strings:
        $s1 = "https://discord.com/api/webhooks/" ascii wide nocase
        $s2 = "https://cdn.discordapp.com/attachments/" ascii wide nocase
        $s3 = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va" ascii wide
        $s4 = "aHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobW" ascii wide
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_IExecuteCommandCOM {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding command execution via IExecuteCommand COM object"
    strings:
        $r1 = "Classes\\Folder\\shell\\open\\command" ascii wide nocase
        $k1 = "DelegateExecute" ascii wide
        $s1 = "/EXEFilename \"{0}" ascii wide
        $s2 = "/WindowState \"\"" ascii wide
        $s3 = "/PriorityClass \"\"32\"\" /CommandLine \"" ascii wide
        $s4 = "/StartDirectory \"" ascii wide
        $s5 = "/RunAs" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($r*) and 1 of ($k*)) or (all of ($s*)))
}

rule INDICATOR_SUSPICIOUS_EXE_WMI_EnumerateVideoDevice {
    meta:
        author = "ditekSHen"
        description = "Detects executables attemping to enumerate video devices using WMI"
    strings:
        $q1 = "Select * from Win32_CacheMemory" ascii wide nocase
        $d1 = "{860BB310-5D01-11d0-BD3B-00A0C911CE86}" ascii wide
        $d2 = "{62BE5D10-60EB-11d0-BD3B-00A0C911CE86}" ascii wide
        $d3 = "{55272A00-42CB-11CE-8135-00AA004BB851}" ascii wide
        $d4 = "SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\000" ascii wide nocase
        $d5 = "HardwareInformation.AdapterString" ascii wide
        $d6 = "HardwareInformation.qwMemorySize" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($q*) and 1 of ($d*)) or 3 of ($d*))
}

rule INDICATOR_SUSPICIOUS_EXE_Go_GoLazagne {
    meta:
        author = "ditekSHen"
        description = "Detects Go executables using GoLazagne"
    strings:
        $s1 = "/goLazagne/" ascii nocase
        $s2 = "Go build ID:" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_CSPROJ {
    meta:
        author = "ditekSHen"
        description = "Detects suspicious .CSPROJ files"
    strings:
        $s1 = "ToolsVersion=" ascii
        $s2 = "/developer/msbuild/" ascii
        $x1 = "[DllImport(\"\\x" ascii
        $x2 = "VirtualAlloc(" ascii nocase
        $x3 = "CallWindowProc(" ascii nocase
    condition:
        uint32(0) == 0x6f72503c and (all of ($s*) and 2 of ($x*))
}

rule INDICATOR_SUSPICIOUS_Sandbox_Evasion_FilesComb {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing specific set of files observed in sandob anti-evation, and Emotet"
    strings:
        $s1 = "c:\\take_screenshot.ps1" ascii wide nocase
        $s2 = "c:\\loaddll.exe" ascii wide nocase
        $s3 = "c:\\email.doc" ascii wide nocase
        $s4 = "c:\\email.htm" ascii wide nocase
        $s5 = "c:\\123\\email.doc" ascii wide nocase
        $s6 = "c:\\123\\email.docx" ascii wide nocase
        $s7 = "c:\\a\\foobar.bmp" ascii wide nocase
        $s8 = "c:\\a\\foobar.doc" ascii wide nocase
        $s9 = "c:\\a\\foobar.gif" ascii wide nocase
        $s10 = "c:\\symbols\\aagmmc.pdb" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 6 of them
}

rule INDICATOR_SUSPICIOUS_Sandbox_Evasion_VirtDrvComb {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing combination of virtualization drivers"
    strings:
        $p1 = "prleth.sys" ascii wide
        $p2 = "prlfs.sys" ascii wide
        $p3 = "prlmouse.sys" ascii wide
        $p4 = "prlvideo.sys	" ascii wide
        $p5 = "prltime.sys" ascii wide
        $p6 = "prl_pv32.sys" ascii wide
        $p7 = "prl_paravirt_32.sys" ascii wide
        $vb1 = "VBoxMouse.sys" ascii wide
        $vb2 = "VBoxGuest.sys" ascii wide
        $vb3 = "VBoxSF.sys" ascii wide
        $vb4 = "VBoxVideo.sys" ascii wide
        $vb5 = "vboxdisp.dll" ascii wide
        $vb6 = "vboxhook.dll" ascii wide
        $vb7 = "vboxmrxnp.dll" ascii wide
        $vb8 = "vboxogl.dll" ascii wide
        $vb9 = "vboxoglarrayspu.dll" ascii wide
        $vb10 = "vboxoglcrutil.dll" ascii wide
        $vb11 = "vboxoglerrorspu.dll" ascii wide
        $vb12 = "vboxoglfeedbackspu.dll" ascii wide
        $vb13 = "vboxoglpackspu.dll" ascii wide
        $vb14 = "vboxoglpassthroughspu.dll" ascii wide
        $vb15 = "vboxservice.exe" ascii wide
        $vb16 = "vboxtray.exe" ascii wide
        $vb17 = "VBoxControl.exe" ascii wide
        $vp1 = "vmsrvc.sys" ascii wide
        $vp2 = "vpc-s3.sys" ascii wide
        $vw1 = "vmmouse.sys" ascii wide
        $vw2 = "vmnet.sys" ascii wide
        $vw3 = "vmxnet.sys" ascii wide
        $vw4 = "vmhgfs.sys" ascii wide
        $vw5 = "vmx86.sys" ascii wide
        $vw6 = "hgfs.sys" ascii wide
    condition:
         uint16(0) == 0x5a4d and (
             (2 of ($p*) and (2 of ($vb*) or 2 of ($vp*) or 2 of ($vw*))) or
             (2 of ($vb*) and (2 of ($p*) or 2 of ($vp*) or 2 of ($vw*))) or
             (2 of ($vp*) and (2 of ($p*) or 2 of ($vb*) or 2 of ($vw*))) or
             (2 of ($vw*) and (2 of ($p*) or 2 of ($vb*) or 2 of ($vp*)))
         )
}

rule INDICATOR_SUSPICIOUS_EXE_NoneWindowsUA {
    meta:
        author = "ditekSHen"
        description = "Detects Windows executables referencing non-Windows User-Agents"
    strings:
        $ua1 = "Mozilla/5.0 (Macintosh; Intel Mac OS" wide ascii
        $ua2 = "Mozilla/5.0 (iPhone; CPU iPhone OS" ascii wide
        $ua3 = "Mozilla/5.0 (Linux; Android " ascii wide
        $ua4 = "Mozilla/5.0 (PlayStation " ascii wide
        $ua5 = "Mozilla/5.0 (X11; " wide ascii
        $ua6 = "Mozilla/5.0 (Windows Phone " ascii wide
        $ua7 = "Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)" wide ascii
        $ua8 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0)" wide ascii
        $ua9 = "HTC_Touch_3G Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 7.11)" wide ascii
        $ua10 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows Phone OS 7.0; Trident/3.1; IEMobile/7.0; Nokia;N70)" wide ascii
        $ua11 = "Mozilla/5.0 (BlackBerry; U; BlackBerry " wide ascii
        $ua12 = "Mozilla/5.0 (iPad; CPU OS" wide ascii
        $ua13 = "Mozilla/5.0 (iPad; U;" ascii wide
        $ua14 = "Mozilla/5.0 (IE 11.0;" ascii wide
        $ua15 = "Mozilla/5.0 (Android;" ascii wide
        $ua16 = "User-Agent: Internal Wordpress RPC connection" ascii wide
    condition:
         uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_SUSPICIOUS_VM_Evasion_MACAddrComb {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing virtualization MAC addresses"
    strings:
        $s1 = "00:03:FF" ascii wide nocase
        $s2 = "00:05:69" ascii wide nocase
        $s3 = "00:0C:29" ascii wide nocase
        $s4 = "00:16:3E" ascii wide nocase
        $s5 = "00:1C:14" ascii wide nocase
        $s6 = "00:1C:42" ascii wide nocase
        $s7 = "00:50:56" ascii wide nocase
        $s8 = "08:00:27" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_EXE_CC_Regex {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing credit card regular expressions"
    strings:
        // Amex / Express Card
        $s1 = "^3[47][0-9]{13}$" ascii wide nocase
        $s2 = "3[47][0-9]{13}$" ascii wide nocase
        $s3 = "37[0-9]{2}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
        // BCGlobal
        $s4 = "^(6541|6556)[0-9]{12}$" ascii wide nocase
        // Carte Blanche Card
        $s5 = "^389[0-9]{11}$" ascii wide nocase
        // Diners Club Card
        $s6 = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$" ascii wide nocase
        // Discover Card
        $s7 = "6(?:011|5[0-9]{2})[0-9]{12}$" ascii wide nocase
        $s8 = "6011\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
        // Insta Payment Card
        $s9 = "^63[7-9][0-9]{13}$" ascii wide nocase
        // JCB Card
        $s10 = "^(?:2131|1800|35\\d{3})\\d{11}$" ascii wide nocase
        // KoreanLocalCard
        $s11 = "^9[0-9]{15}$" ascii wide nocase
        // Laser Card
        $s12 = "^(6304|6706|6709|6771)[0-9]{12,15}$" ascii wide nocase
        // Maestro Card
        $s13 = "^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" ascii wide nocase
        // Mastercard
        $s14 = "5[1-5][0-9]{14}$" ascii wide nocase
        // Solo Card
        $s15 = "^(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15}$" ascii wide nocase
        // Switch Card
        $s16 = "^(4903|4905|4911|4936|6333|6759)[0-9]{12}|(4903|4905|4911|4936|6333|6759)[0-9]{14}|(4903|4905|4911|4936|6333|6759)[0-9]{15}|564182[0-9]{10}|564182[0-9]{12}|564182[0-9]{13}|633110[0-9]{10}|633110[0-9]{12}|633110[0-9]{13}$" ascii wide nocase
        // Union Pay Card
        $s17 = "^(62[0-9]{14,17})$" ascii wide nocase
        // Visa Card
        $s18 = "4[0-9]{12}(?:[0-9]{3})?$" ascii wide nocase
        // Visa Master Card
        $s19 = "^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$" ascii wide nocase
        $s20 = "4[0-9]{3}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
        $a21 = "^[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}"ascii wide nocase
    condition:
         (uint16(0) == 0x5a4d and 2 of them) or (4 of them)
}

rule INDICATOR_SUSPICIOUS_EXE_Discord_Regex {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing Discord tokens regular expressions"
    strings:
        $s1 = "[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}|mfa\\.[a-zA-Z0-9_\\-]{84}" ascii wide nocase
    condition:
         (uint16(0) == 0x5a4d and all of them) or all of them
}

rule INDICATOR_SUSPICIOUS_EXE_VaultSchemaGUID {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing Windows vault credential objects. Observed in infostealers"
    strings:
        // Windows Secure Note
        $s1 = "2F1A6504-0641-44CF-8BB5-3612D865F2E5" ascii wide
        // Windows Web Password Credential
        $s2 = "3CCD5499-87A8-4B10-A215-608888DD3B55" ascii wide
        // Windows Credential Picker Protector
        $s3 = "154E23D0-C644-4E6F-8CE6-5069272F999F" ascii wide
        // Web Credentials
        $s4 = "4BF4C442-9B8A-41A0-B380-DD4A704DDB28" ascii wide
        // Windows Credentials
        $s5 = "77BC582B-F0A6-4E15-4E80-61736B6F3B29" ascii wide
        // Windows Domain Certificate Credential
        $s6 = "E69D7838-91B5-4FC9-89D5-230D4D4CC2BC" ascii wide
        // Windows Domain Password Credential
        $s7 = "3E0E35BE-1B77-43E7-B873-AED901B6275B" ascii wide
        // Windows Extended Credential
        $s8 = "3C886FF3-2669-4AA2-A8FB-3F6759A77548" ascii wide
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_SUSPICIOUS_AntiVM_UNK01 {
    meta:
        author = "ditekSHen"
        description = "Detects memory artifcats referencing specific combination of anti-VM checks"
    strings:
        $s1 = "vmci.s" fullword ascii wide
        $s2 = "vmmemc" fullword ascii wide
        $s3 = "qemu-ga.exe" fullword ascii wide
        $s4 = "qga.exe" fullword ascii wide
        $s5 = "windanr.exe" fullword ascii wide
        $s6 = "vboxservice.exe" fullword ascii wide
        $s7 = "vboxtray.exe" fullword ascii wide
        $s8 = "vmtoolsd.exe" fullword ascii wide
        $s9 = "prl_tools.exe" fullword ascii wide
        $s10 = "7869.vmt" fullword ascii wide
        $s11 = "qemu" fullword ascii wide
        $s12 = "virtio" fullword ascii wide
        $s13 = "vmware" fullword ascii wide
        $s14 = "vbox" fullword ascii wide
        $s15 = "%systemroot%\\system32\\ntdll.dll" fullword ascii wide
    condition:
         uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_AntiVM_WMIC {
    meta:
        author = "ditekSHen"
        description = "Detects memory artifcats referencing WMIC commands for anti-VM checks"
    strings:
        $s1 = "wmic process where \"name like '%vmwp%'\"" ascii wide nocase
        $s2 = "wmic process where \"name like '%virtualbox%'\"" ascii wide nocase
        $s3 = "wmic process where \"name like '%vbox%'\"" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_SUSPICIOUS_EnableSMBv1 {
    meta:
        author = "ditekSHen"
        description = "Detects binaries with PowerShell command enable SMBv1"
    strings:
        $s1 = "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_SUSPICIOUS_EnableNetworkDiscovery {
    meta:
        author = "ditekSHen"
        description = "Detects binaries manipulating Windows firewall to enable permissive network discovery"
    strings:
        $s1 = "netsh advfirewall firewall set rule group=\"Network Discovery\" new enable=Yes" ascii wide nocase
        $s2 = "netsh advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=Yes" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_AuthApps {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many authentication apps. Observed in information stealers"
    strings:
        $s1 = "WinAuth\\winauth.xml" ascii wide nocase
        $s2 = "Authy Desktop\\Local" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_RDP {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination manipulating RDP / Terminal Services"
    strings:
        // Beginning with Windows Server 2008 and Windows Vista, this policy no longer has any effect
        // https://docs.microsoft.com/en-us/windows/win32/msi/enableadmintsremote
        $r1 = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" ascii wide nocase
        $k1 = "EnableAdminTSRemote" fullword ascii wide nocase
        // Whether basic Terminal Services functions are enabled
        $r2 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
        $k2 = "TSEnabled" fullword ascii wide nocase
        // Terminal Device Driver Attributes
        // Terminal Services hosts and configurations
        $r3 = "SYSTEM\\CurrentControlSet\\Services\\TermDD" ascii wide nocase
        $r4 = "SYSTEM\\CurrentControlSet\\Services\\TermService" ascii wide nocase
        $k3 = "Start" fullword ascii wide nocase
        // Allows or denies connecting to Terminal Services
        $r5 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
        $k4 = "fDenyTSConnections" fullword ascii wide nocase
        // RDP Port Number
        $r6 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\RDPTcp" ascii wide nocase
        $r7 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp" ascii wide nocase
        $r8 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii wide nocase
        $k5 = "PortNumber" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 5 of ($r*) and 3 of ($k*)
}

rule INDICATOR_SUSPICIOUS_EXE_Undocumented_WinAPI_Kerberos {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing undocumented kerberos Windows APIs and obsereved in malware"
    strings:
        // Undocumented Kerberos-related functions
        // Reference: https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/ (KdcSponge)
        // Reference: https://us-cert.cisa.gov/ncas/current-activity/2021/11/19/updated-apt-exploitation-manageengine-adselfservice-plus
        // New Sample: e391c2d3e8e4860e061f69b894cf2b1ba578a3e91de610410e7e9fa87c07304c
        $kdc1 = "KdcVerifyEncryptedTimeStamp" ascii wide nocase
        $kdc2 = "KerbHashPasswordEx3" ascii wide nocase
        $kdc3 = "KerbFreeKey" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and all of ($kdc*)
}

rule INDICATOR_SUSPICIOUS_EXE_NKN_BCP2P {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing NKN Blockchain P2P network"
    strings:
        $x1 = "/nknorg/nkn-sdk-go." ascii
        $x2 = "://seed.nkn.org" ascii
        $x3 = "/nknorg/nkn/" ascii
        $s1 = ").NewNanoPayClaimer" ascii
        $s2 = ").IncrementAmount" ascii
        $s3 = ").BalanceByAddress" ascii
        $s4 = ").TransferName" ascii
        $s5 = ".GetWsAddr" ascii
        $s6 = ".GetNodeStateContext" ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or all of ($s*))
}
