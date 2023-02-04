rule Avalon {
    meta:
      author = "ditekshen"
      description = "Avalon infostealer payload"
      cape_type = "Avalon payload"
    strings:
      $s1 = "Parsecards" fullword ascii
      $s2 = "Please_Gofuckyouself" fullword ascii
      $s3 = "GetDomainDetect" fullword ascii
      $s4 = "GetTotalCommander" fullword ascii
      $s5 = "KnownFolder" fullword ascii
      $s6 = "set_hidden" fullword ascii
      $s7 = "set_system" fullword ascii

      $l1 = "\\DomainDetect.txt" wide
      $l2 = "\\Grabber_Log.txt" wide
      $l3 = "\\Programs.txt" wide
      $l4 = "\\Passwords_Edge.txt" wide
      $l5 = "\\KL.txt" wide

      $w1 = "dont touch" fullword wide
      $w2 = "Grabber" fullword wide
      $w3 = "Keylogger" fullword wide
      $w4 = "password-check" fullword wide
      $w5 = "H4sIAAAAAAAEA" wide

      $p1 = "^(?!:\\/\\/)([a-zA-Z0-9-_]+\\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\\.[a-zA-Z]{2,11}?$" wide
      $p2 = "^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$" wide
   condition:
      uint16(0) == 0x5a4d and 8 of them
}
