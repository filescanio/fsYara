// source: https://github.com/Neo23x0/signature-base/blob/master/yara/crime_andromeda_jun17.yar

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-30
   Identifier: WORM_RETADUP
   Reference: http://blog.trendmicro.com/trendlabs-security-intelligence/information-stealer-found-hitting-israeli-hospitals/
*/

/* Rule Set ----------------------------------------------------------------- */

rule Andromeda_MalBot_Jun_1A {
   meta:
      description = "Detects a malicious Worm Andromeda / RETADUP"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/information-stealer-found-hitting-israeli-hospitals/"
      date = "2017-06-30"
      modified = "2022-12-21"
      score = 50
      hash1 = "3c223bbf83ac2f91c79383a53ed15b0c8ffe2caa1bf52b26c17fd72278dc7ef9"
      hash2 = "73cecc67bb12cf5a837af9fba15b7792a6f1a746b246b34f8ed251c4372f1a98"
      hash3 = "66035cc81e811735beab573013950153749b02703eae58b90430646f6e3e3eb4"
      hash4 = "42a02e6cf7c424c12f078fca21805de072842ec52a25ea87bd7d53e7feb536ed"
      id = "42ee6ba3-85ea-5369-bd9b-8ffdec6e17bc"
   strings:
      $x1 = "%temp%\\FolderN\\name.exe" fullword wide
      $x2 = "%temp%\\FolderN\\name.exe.lnk" fullword wide
      $x3 = "\\Startup\\name.exe" wide
      $x4 = "firefox.exe.exe" fullword wide
      $x5 = "\\Desktop\\New folder\\dark.exe" wide
      $x6 = "\\x86\\Release\\word.pdb" ascii
      $x7 = "\\obj\\Release\\botkill.pdb" ascii

      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s2 = "svhost.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) or 2 of them )
}
