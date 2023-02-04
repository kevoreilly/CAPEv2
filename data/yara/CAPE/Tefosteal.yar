rule Tefosteal {
    meta:
        author = "ditekshen"
        description = "Tefosteal payload"
        cape_type = "Tefosteal payload"
    strings:
        $s1 = "netsh wlan show networks mode=bssid" nocase fullword wide
        $s2 = "LoginCredentialService.GetLoginCredentials$" ascii
        $s3 = "DefaultLoginCredentials.LoginEventUsrPw$" ascii
        $s4 = "SEC_E_NO_KERB_KEY" wide
        $s5 = "TList<System.Zip.TZipHeader>." ascii
        $s6 = "_Password.txt" fullword wide nocase
        $s7 = "_Cookies.txt" fullword wide nocase
        $f1 = "\\InfoPC\\BSSID.txt" wide
        $f2 = "\\Files\\Telegram\\" wide
        $f3 = "\\InfoPC\\Screenshot.png" wide
        $f4 = "\\InfoPC\\Systeminfo.txt" wide
        $f5 = "\\Steam\\config" wide
        $f6 = "\\delete.vbs" wide
    condition:
        uint16(0) == 0x5a4d and 4 of ($s*) and 2 of ($f*)
}
