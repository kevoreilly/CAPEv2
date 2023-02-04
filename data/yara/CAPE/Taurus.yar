rule Taurus {
    meta:
      author = "ditekSHen"
      description = "Taurus infostealer payload"
      cape_type = "Taurus Payload"
    strings:
      $s1 = "t.me/taurus_se" ascii
      $s2 = "rus_seller@explo" ascii
      $s3 = "/c timeout /t 3  & del /f /q" ascii
      $s4 = "MyAwesomePrefix" ascii
      $txt1 = "LogInfo.txt" fullword ascii
      $txt2 = "Information.txt" fullword ascii
      $txt3 = "General\\passwords.txt" fullword ascii
      $txt4 = "General\\forms.txt" fullword ascii
      $txt5 = "General\\cards.txt" fullword ascii
      $txt6 = "Installed Software.txt" fullword ascii
      $txt7 = "Crypto Wallets\\WalletInfo.txt" fullword ascii
      $txt8 = "cookies.txt" fullword ascii
      $url1 = "/cfg/" wide
      $url2 = "/loader/complete/" wide
      $url3 = "/log/" wide
      $url4 = "/dlls/" wide
      $upat = /\.exe;;;\d;\d;\d\]\|\[http/

      $x1 = "Vaultcli.dll" fullword ascii
      $x2 = "Bcrypt.dll" fullword ascii
      $x3 = "*.localstor" ascii
      $x4 = "operator<=>" fullword ascii
      $x5 = ".data$rs" fullword ascii
      $x6 = "https_discordap" ascii
      $o1 = { 53 56 8b 75 08 8d 85 64 ff ff ff 57 6a ff 6a 01 }
      $o2 = { 6a 00 68 00 04 00 00 ff b5 a8 fe ff ff ff b5 ac }
      $o3 = { ff 75 0c 8d 85 44 ff ff ff 50 e8 aa f7 ff ff 8b }
      $o4 = { 8b 47 04 c6 40 19 01 8d 85 6c ff ff ff 8b 0f 50 }
      $o5 = { 8d 8d ?? ff ff ff e8 5b }
    condition:
        ((3 of ($s*) or (6 of ($txt*) and 2 of ($s*)) or ($upat and 1 of ($s*) and 2 of ($txt*)) or (all of ($url*) and (2 of ($txt*) or 1 of ($s*)))) or (uint16(0) == 0x5a4d and all of ($x*) or (all of ($o*) and 3 of ($x*))))
}
