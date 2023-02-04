rule Plurox {
    meta:
      author = "ditekshen"
      description = "Plurox backdoor payload"
      cape_type = "Plurox payload"
    strings:
      $s1 = "autorun.c" fullword ascii
      $s2 = "launcher.c" fullword ascii
      $s3 = "loader.c" fullword ascii
      $s4 = "stealth.c" fullword ascii
      $s5 = "RunFromMemory" fullword ascii
   condition:
      uint16(0) == 0x5a4d and all of them
}
