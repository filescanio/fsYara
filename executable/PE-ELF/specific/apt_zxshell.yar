// source: https://github.com/Neo23x0/signature-base/blob/007d9ddee386f68aca3a3aac5e1514782f02ed2d/yara/apt_zxshell.yar

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-08
   Identifier: ZxShell Related Malware (same C2)
   Reference: https://blogs.rsa.com/cat-phishing/
*/

/* Rule Set ----------------------------------------------------------------- */

rule ZxShell_Related_Malware_CN_Group_Jul17_1 {
   meta:
      description = "Detects a ZxShell related sample from a CN threat group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blogs.rsa.com/cat-phishing/"
      date = "2017-07-08"
      hash1 = "ef56c2609bc1b90f3e04745890235e6052a4be94e35e38b6f69b64fb17a7064e"
      id = "a91e39bb-1bb3-54a8-b684-d673c445375c"
      score = 75
   strings:
      $x1 = "CMD.EXE /C NET USER GUEST /ACTIVE:yes && NET USER GUEST ++++++" ascii
      $x2 = "system\\cURRENTcONTROLSET\\sERVICES\\tERMSERVICE" fullword ascii
      $x3 = "\\secivreS\\teSlortnoCtnerruC\\METSYS" ascii /* reversed goodware string 'SYSTEM\\CurrentControlSet\\Services\\' */
      $x4 = "system\\cURRENTCONTROLSET\\cONTROL\\tERMINAL sERVER" fullword ascii
      $x5 = "sOFTWARE\\mICROSOFT\\iNTERNET eXPLORER\\mAIN" fullword ascii
      $x6 = "eNABLEaDMINtsREMOTE" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule ZxShell_Related_Malware_CN_Group_Jul17_2 {
   meta:
      description = "Detects a ZxShell related sample from a CN threat group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blogs.rsa.com/cat-phishing/"
      date = "2017-07-08"
      hash1 = "204273675526649b7243ee48efbb7e2bc05239f7f9015fbc4fb65f0ada64759e"
      id = "37c1f26b-4b4f-510e-a7b7-b2afb17d6e71"
   strings:
      $u1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
      $u2 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
      $u3 = "User-Agent:Mozilla/5.0 (X11; U; Linux i686; en-US; re:1.4.0) Gecko/20080808 Firefox/%d.0" fullword ascii
      $u4 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii

      $x1 = "\\\\%s\\admin$\\g1fd.exe" fullword ascii
      $x2 = "C:\\g1fd.exe" fullword ascii
      $x3 = "\\\\%s\\C$\\NewArean.exe" fullword ascii

      $s0 = "at \\\\%s %d:%d %s" fullword ascii
      $s1 = "%c%c%c%c%ccn.exe" fullword ascii
      $s2 = "hra%u.dll" fullword ascii
      $s3 = "Referer: http://%s:80/http://%s" fullword ascii
      $s5 = "Accept-Language: zh-cn" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) or 3 of them )
}

rule ZxShell_Related_Malware_CN_Group_Jul17_3 {
   meta:
      description = "Detects a ZxShell related sample from a CN threat group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blogs.rsa.com/cat-phishing/"
      date = "2017-07-08"
      hash1 = "2e5cf8c785dc081e5c2b43a4a785713c0ae032c5f86ccbc7abf5c109b8854ed7"
      id = "1900b861-b4a2-50b5-a639-3eb442072139"
   strings:
      $s1 = "%s\\nt%s.dll" fullword ascii
      $s2 = "RegQueryValueEx(Svchost\\netsvcs)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and all of them )
}

rule ZxShell_Jul17 {
   meta:
      description = "Detects a ZxShell - CN threat group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blogs.rsa.com/cat-phishing/"
      date = "2017-07-08"
      hash1 = "5d2a4cde9fa7c2fdbf39b2e2ffd23378d0c50701a3095d1e91e3cf922d7b0b16"
      id = "1b009b20-5a19-5cac-aaaf-ca61310eab9f"
      score = 80
   strings:
      $x1 = "zxplug -add" fullword ascii
      $x2 = "getxxx c:\\xyz.dll" fullword ascii
      $x3 = "downfile -d c:\\windows\\update.exe" fullword ascii
      $x4 = "-fromurl http://x.x.x/x.dll" fullword ascii
      $x5 = "ping 127.0.0.1 -n 7&cmd.exe /c net start %s" fullword ascii
      $x6 = "ZXNC -e cmd.exe x.x.x.x" fullword ascii
      $x7 = "(bind a cmdshell)" fullword ascii
      $x8 = "ZXFtpServer 21 20 zx" fullword ascii
      $x9 = "ZXHttpServer" fullword ascii
      $x10 = "c:\\error.htm,.exe|c:\\a.exe,.zip|c:\\b.zip\"" fullword ascii
      $x11 = "c:\\windows\\clipboardlog.txt" fullword ascii
      $x12 = "AntiSniff -a wireshark.exe" fullword ascii
      $x13 = "c:\\windows\\keylog.txt" fullword ascii
   condition:
      ( filesize < 10000KB and 1 of them ) or 3 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-12-11
   Identifier: ZxShell
   Reference: https://goo.gl/snc85M
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule ZXshell_20171211_chrsben {
   meta:
      description = "Detects ZxShell variant surfaced in Dec 17"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/snc85M"
      date = "2017-12-11"
      hash1 = "dd01e7a1c9b20d36ea2d961737780f2c0d56005c370e50247e38c5ca80dcaa4f"
      id = "3bbfddb8-011a-52dd-b0c8-b35e6f740507"
   strings:
      $x1 = "ncProxyXll" fullword ascii

      $s1 = "Uniscribe.dll" fullword ascii
      $s2 = "GetModuleFileNameDll" fullword ascii
      $s4 = "$Hangzhou Shunwang Technology Co.,Ltd0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and (
        pe.imphash() == "de481441d675e9aca4f20bd8e16a5faa" or
        pe.exports("PerfectWorld") or
        pe.exports("ncProxyXll") or
        1 of ($x*) or
        2 of them
      )
}
