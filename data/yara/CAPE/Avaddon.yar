rule Avaddon {
    meta:
      author = "ditekshen"
      description = "Avaddon Payload"
      cape_type = "Avaddon payload"
    strings:
      $s1 = "\\IMAGEM~1.%d\\VISUA~1\\BIN\\%s.exe" ascii
      $s2 = "\\IMAGEM~1.%.2d-\\VISUA~1\\BIN\\%s.exe" ascii
      $s3 = "\\IMAGEM~1.%d-Q\\VISUA~1\\BIN\\%s.exe" ascii
      $s4 = "\\IMAGEM~1.%d\\%s.exe" ascii
      $s5 = "EW6]>mFXDS?YBi?W5] CY 4Z8Y BY7Y BZ8Z CY7Y AY8Z CZ8Y!Y:Z" ascii
      $s6 = "FY  AY 'Z      ;W      @Y  @Y 'Z    Y  @Y (Z" ascii
      $s7 = "\"rcid\":\"" fullword ascii
      $s8 = "\"ip\":\"" fullword ascii wide
      $s9 = ".?AUANEventIsGetExternalIP@@" fullword ascii
      $s10 = ".?AUANEventGetCpuMax@@" fullword ascii
      $s11 = "\"hdd\":\"" fullword ascii
      $s12 = "\"ext\":\"" fullword ascii wide
   condition:
      uint16(0) == 0x5a4d and 8 of them
}
