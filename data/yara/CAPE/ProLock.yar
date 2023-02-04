rule ProLock {
    meta:
      author = "ditekshen"
      description = "ProLock ransomware payload"
      cape_type = "ProLock payload"
    strings:
      $s1 = ".flat" fullword ascii
      $s2 = ".data" fullword ascii
      $s3 = ".api" fullword ascii
      $s4 = "RtlZeroMemory" fullword ascii
      $s5 = "LoadLibraryA" fullword ascii
      $s6 = "Sleep" fullword ascii
      $s7 = "lstrcatA" fullword ascii
      $s8 = { 55 89 E5 8B 45 08 EB 00 89 45 EC 8D 15 4F 10 40 00 8D 05 08 10 40 00 83 E8 08 29 C2 8B 45 EC 01 C2 31 }
   condition:
      uint16(0) == 0x5a4d and all of them
}
