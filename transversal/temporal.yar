rule SUSP_INDICATOR_RTF_MalVer_Objects {
   strings:
      $str1 = "123456789100987654321random"
   condition:
      uint32(0) == 0x74725c7b and $str1
}