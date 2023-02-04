rule SlothfulMedia {
     meta:
      author = "ditekshen"
      description = "SlothfulMedia backdoor payload"
      cape_type = "SlothfulMedia payload"
    strings:
      $x1 = /ExtKeylogger(Start|Stop)/ fullword ascii
      $x2 = /ExtService(Add|Delete|Start|Stop)/ fullword ascii
      $x3 = /ExtRegKey(Add|Del)/ fullword ascii
      $x4 = /ExtRegItem(Add|Del)/ fullword ascii
      $x5 = "ExtUnload" fullword ascii

      $s1 = "Local Security Process" fullword wide
      $s2 = "Global%s%d" fullword wide
      $s3 = "%s%s_%d.dat" fullword wide
      $s4 = "\\AppIni" fullword wide
      $s5 = "%s.tmp" fullword wide
      $s6  = "\\SetupUi" fullword wide
      $s7 = "%s|%s|%s|%s" fullword wide
      $s8 = "\\ExtInfo" fullword wide

      $cnc1 = "/v?m=" fullword ascii
      $cnc2 = "%s&i=%d" fullword ascii
      $cnc3 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75" fullword ascii
      $cnc4 = "Content-Length: %d" fullword ascii
    condition:
      uint16(0) == 0x5a4d and (3 of ($x*) or 7 of ($s*) or all of ($cnc*) or (1 of ($x*) and 4 of ($s*)))
}
