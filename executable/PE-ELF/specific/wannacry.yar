/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/

// source: https://github.com/Yara-Rules/rules/blob/master/malware/RANSOM_MS17-010_Wannacrypt.yar
// source: https://github.com/reversinglabs/reversinglabs-yara-rules/tree/develop/yara/ransomware/Win32.Ransomware.WannaCry.yara
// refined rules

import "pe"

private rule MS17_010_WanaCry_worm : refined {
	meta:
		description = "Worm exploiting MS17-010 and dropping WannaCry Ransomware"
		author = "Felipe Molina (@felmoltor)"
		reference = "https://www.exploit-db.com/exploits/41987/"
		date = "2017/05/12"
	strings:
		$ms17010_str1="PC NETWORK PROGRAM 1.0"
		$ms17010_str2="LANMAN1.0"
		$ms17010_str3="Windows for Workgroups 3.1a"
		$ms17010_str4="__TREEID__PLACEHOLDER__"
		$ms17010_str5="__USERID__PLACEHOLDER__"
		$wannacry_payload_substr1 = "h6agLCqPqVyXi2VSQ8O6Yb9ijBX54j"
		$wannacry_payload_substr2 = "h54WfF9cGigWFEx92bzmOd0UOaZlM"
		$wannacry_payload_substr3 = "tpGFEoLOU6+5I78Toh/nHs/RAP"

	condition:
		all of them
}

/*
Four YARA rules to check for payloads on systems. Thanks to sinkholing, encyrption may not occur, BUT you may still have binaries lying around.
If you get a match for "WannaDecryptor" and not for Wanna_Sample, then you may have a variant!
 
Check out http://yara.readthedocs.io on how to write and add a rule as below and index your
rule by the sample hashes.  Add, share, rinse and repeat!
*/
 
rule WannaDecryptor {
    meta:
        description = "Detection for common strings of WannaDecryptor"

    strings:
        $id1 = "taskdl.exe"
        $id2 = "taskse.exe"
        $id3 = "r.wnry"
        $id4 = "s.wnry"
        $id5 = "t.wnry"
        $id6 = "u.wnry"
        $id7 = "msg/m_"

    condition:
        3 of them
}

rule Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549 {
    meta:
        description = "Specific sample match for WannaCryptor"
        MD5 = "84c82835a5d21bbcf75a61706d8ab549"
        SHA1 = "5ff465afaabcbf0150d1a3ab2c2e74f3a4426467"
        SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        INFO = "Looks for 'taskdl' and 'taskse' at known offsets"
 
    strings:
        $taskdl = { 00 74 61 73 6b 64 6c }
        $taskse = { 00 74 61 73 6b 73 65 }

    condition:
        $taskdl at 3419456 and $taskse at 3422953
}

rule Wanna_Sample_4da1f312a214c07143abeeafb695d904 {
        meta:
                description = "Specific sample match for WannaCryptor"
                MD5 = "4da1f312a214c07143abeeafb695d904"
                SHA1 = "b629f072c9241fd2451f1cbca2290197e72a8f5e"
                SHA256 = "aee20f9188a5c3954623583c6b0e6623ec90d5cd3fdec4e1001646e27664002c"
                INFO = "Looks for offsets of r.wry and s.wry instances"
 
        strings:
                $rwnry = { 72 2e 77 72 79 }
                $swnry = { 73 2e 77 72 79 }
 
        condition:
                $rwnry at 88195 and $swnry at 88656 and $rwnry at 4495639
}

private rule NHS_Strain_Wanna: NHS_Strain_Wanna refined {
    meta:
        description = "Detection for worm-strain bundle of Wcry, DOublePulsar"
        MD5 = "db349b97c37d22f5ea1d1841e3c89eb4"
        SHA1 = "e889544aff85ffaf8b0d0da705105dee7c97fe26"
        SHA256 = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
        INFO = "Looks for specific offsets of c.wnry and t.wnry strings"

    strings:
        $cwnry = { 63 2e 77 6e 72 79 }
        $twnry = { 74 2e 77 6e 72 79 }

    condition:
        $cwnry at 262324 and $twnry at 267672 and $cwnry at 284970  
}

private rule ransom_telefonica : TELEF refined {
  meta:
    author = "Jaume Martin <@Xumeiquer>"
    description = "Ransmoware Telefonica"
    date = "2017-05-13"
    reference = "http://www.elmundo.es/tecnologia/2017/05/12/59158a8ce5fdea194f8b4616.html"
    md5 = "7f7ccaa16fb15eb1c7399d422f8363e8"
    sha256 = "2584e1521065e45ec3c17767c065429038fc6291c091097ea8b22c8a502c41dd"
  strings:
    $a = "RegCreateKeyW" wide ascii nocase
    $b = "cmd.exe /c"
    $c = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
    $d = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" ascii
    $e = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii
    $f = "tasksche.exe"
  condition:
    uint16(0) == 0x5A4D and $a and for all of ($b, $c, $d, $e, $f) : (@ > @a)
}

private rule Wanna_Cry_Ransomware_Generic : refined{
       meta:
              description = "Detects WannaCry Ransomware on Disk and in Virtual Page"
              author = "US-CERT Code Analysis Team"
              reference = "not set"                                        
              date = "2017/05/12"
       hash0 = "4DA1F312A214C07143ABEEAFB695D904"
       strings:
              $s0 = {410044004D0049004E0024}
              $s1 = "WannaDecryptor"
              $s2 = "WANNACRY"
              $s3 = "Microsoft Enhanced RSA and AES Cryptographic"
              $s4 = "PKS"
              $s5 = "StartTask"
              $s6 = "wcry@123"
              $s7 = {2F6600002F72}
              $s8 = "unzip 0.15 Copyrigh"
              $s9 = "Global\\WINDOWS_TASKOSHT_MUTEX"        
              $s10 = "Global\\WINDOWS_TASKCST_MUTEX"   
             $s11 = {7461736B736368652E657865000000005461736B5374617274000000742E776E7279000069636163}
             $s12 = {6C73202E202F6772616E742045766572796F6E653A46202F54202F43202F5100617474726962202B68}
             $s13 = "WNcry@2ol7"
             $s14 = "wcry@123"
             $s15 = "Global\\MsWinZonesCacheCounterMutexA"
       condition:
              $s0 and $s1 and $s2 and $s3 or $s4 and $s5 and $s6 and $s7 or $s8 and $s9 and $s10 or $s11 and $s12 or $s13 or $s14 or $s15
}

rule WannaCry_Ransomware: refined {
   meta:
      //covers WannaCry_Ransomware_Gen, WannaCry_Ransomware_Dropper
      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (with the help of binar.ly)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
      hash2 = "9fe91d542952e145f2244572f314632d93eb1e8657621087b2ca7f7df2b0cb05"
      hash3 = "8e5b5841a3fe81cade259ce2a678ccb4451725bba71f6662d0cc1f08148da8df"
      hash4 = "4384bf4530fb2e35449a8e01c7e0ad94e3a25811ba94f7847c1e6612bbb45359"
   strings:
      $x1 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
      $x2 = "taskdl.exe" fullword ascii
      $x3 = "tasksche.exe" fullword ascii
      $x4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
      $x5 = "WNcry@2ol7" fullword ascii
      $x6 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
      $x7 = "mssecsvc.exe" fullword ascii
      $x8 = "C:\\%s\\qeriuwjhrf" fullword ascii
      $x9 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii

      $s1 = "C:\\%s\\%s" fullword ascii
      $s2 = "<!-- Windows 10 --> " fullword ascii
      $s3 = "cmd.exe /c \"%s\"" fullword ascii
      $s4 = "msg/m_portuguese.wnry" fullword ascii
      $s5 = "\\\\192.168.56.20\\IPC$" fullword wide
      $s6 = "\\\\172.16.99.5\\IPC$" fullword wide

      $op1 = { 10 ac 72 0d 3d ff ff 1f ac 77 06 b8 01 00 00 00 }
      $op2 = { 44 24 64 8a c6 44 24 65 0e c6 44 24 66 80 c6 44 }
      $op3 = { 18 df 6c 24 14 dc 64 24 2c dc 6c 24 5c dc 15 88 }
      $op4 = { 09 ff 76 30 50 ff 56 2c 59 59 47 3b 7e 0c 7c }
      $op5 = { c1 ea 1d c1 ee 1e 83 e2 01 83 e6 01 8d 14 56 }
      $op6 = { 8d 48 ff f7 d1 8d 44 10 ff 23 f1 23 c1 }

      $gen1 = "__TREEID__PLACEHOLDER__" fullword ascii
      $gen2 = "__USERID__PLACEHOLDER__" fullword ascii
      $gen3 = "Windows for Workgroups 3.1a" fullword ascii
      $gen4 = "PC NETWORK PROGRAM 1.0" fullword ascii
      $gen5 = "LANMAN1.0" fullword ascii


   condition:
      uint16(0) == 0x5a4d and (
        (filesize < 10000KB and ( 1 of ($x*) and 1 of ($s*) or 3 of ($op*)) )
        or filesize < 5000KB and  all of ($gen*)
        )
}

/* Cylance Rule */
 
private rule WannaCry_Ransomware_Dropper : refined{
    meta:
        description = "WannaCry Ransomware Dropper"
        reference = "https://www.cylance.com/en_us/blog/threat-spotlight-inside-the-wannacry-attack.html"
        date = "2017-05-12"

    strings:
        $s1 = "cmd.exe /c \"%s\"" fullword ascii
        $s2 = "tasksche.exe" fullword ascii
        $s3 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
        $s4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
     
    condition:
        uint16(0) == 0x5a4d and filesize < 4MB and all of them
}

rule WannaCry_SMB_Exploit {
    meta:
        description = "WannaCry SMB Exploit"
        reference = "https://www.cylance.com/en_us/blog/threat-spotlight-inside-the-wannacry-attack.html"
        date = "2017-05-12"
     
    strings:
        $s1 = { 53 4D 42 72 00 00 00 00 18 53 C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FE 00 00 40 00 00 62 00 02 50 43 20 4E 45 54 57 4F 52 4B 20 50 52 4F 47 52 41 4D 20 31 2E 30 00 02 4C 41 4E 4D 41 4E 31 2E 30 00 02 57 69 6E 64 6F 77 73 20 66 6F 72 20 57 6F 72 6B 67 72 6F 75 70 73 20 33 2E 31 61 00 02 4C 4D 31 2E 32 58 30 30 32 00 02 4C 41 4E 4D 41 4E 32 2E 31 00 02 4E 54 20 4C 4D 20 30 2E 31 32 00 00 00 00 00 00 00 88 FF 53 4D 42 73 00 00 00 00 18 07 C0 }
     
    condition:
        uint16(0) == 0x5a4d and filesize < 4MB and all of them and pe.imports("ws2_32.dll", "connect") and pe.imports("ws2_32.dll", "send") and pe.imports("ws2_32.dll", "recv") and pe.imports("ws2_32.dll", "socket") and pe.imports("ws2_32.dll", "closesocket")
}

private rule wannacry_static_ransom : wannacry_static_ransom refined {

    meta:
        description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants"
        author = "Blueliv"
        reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"
        date = "2017-05-15"

    strings:
        $mutex01 = "Global\\MsWinZonesCacheCounterMutexA" ascii
        $lang01 = "m_bulgarian.wnr" ascii
        $lang02 = "m_vietnamese.wnry" ascii
        $startarg01 = "StartTask" ascii
        $startarg02 = "TaskStart" ascii
        $startarg03 = "StartSchedule" ascii
        $wcry01 = "WanaCrypt0r" ascii wide
        $wcry02 = "WANACRY" ascii
        $wcry03 = "WANNACRY" ascii
        $wcry04 = "WNCRYT" ascii wide
        $forig01 = ".wnry\x00" ascii
        $fvar01 = ".wry\x00" ascii

    condition:
        ($mutex01 or any of ($lang*)) and ( $forig01 or all of ($fvar*) ) and any of ($wcry*) and any of ($startarg*)

}

rule wannacry_memory_ransom : wannacry_memory_ransom {

    meta:
        description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants in memory"
        author = "Blueliv"
        reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"
        date = "2017-05-15"

    strings:

        $s01 = "%08X.eky"
        $s02 = "%08X.pky"
        $s03 = "%08X.res"
        $s04 = "%08X.dky"
        $s05 = "@WanaDecryptor@.exe"

    condition:
        all of them

}

private rule worm_ms17_010 : worm_ms17_010 refined {

    meta:
        description = "Detects Worm used during 2017-May-12th WannaCry campaign, which is based on ETERNALBLUE"
        author = "Blueliv"
        reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"
        date = "2017-05-15"

    strings:
        $s01 = "__TREEID__PLACEHOLDER__" ascii
        $s02 = "__USERID__PLACEHOLDER__@" ascii
        $s03 = "SMB3"
        $s05 = "SMBu"
        $s06 = "SMBs"
        $s07 = "SMBr"
        $s08 = "%s -m security" ascii
        $s09 = "%d.%d.%d.%d"
        $payloadwin2000_2195 = "\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00"
        $payload2000_50 = "\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00"

    condition:
        all of them

}


rule wannacry_wrapper {
    meta:
        description = "Matches one or more wannacry yara rules"
        author = "Filescan"
        date = "2023-0525"
        vetted_family = "Wannacry"

    condition:
        MS17_010_WanaCry_worm or NHS_Strain_Wanna or worm_ms17_010 or wannacry_static_ransom or WannaCry_Ransomware_Dropper or ransom_telefonica or Wanna_Cry_Ransomware_Generic
}


rule WannCry_m_vbs {
   meta:
      description = "Detects WannaCry Ransomware VBS"
      author = "Florian Roth"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "51432d3196d9b78bdc9867a77d601caffd4adaa66dcac944a5ba0b3112bbea3b"
   strings:
      $x1 = ".TargetPath = \"C:\\@" ascii
      $x2 = ".CreateShortcut(\"C:\\@" ascii
      $s3 = " = WScript.CreateObject(\"WScript.Shell\")" ascii
   condition:
      ( uint16(0) == 0x4553 and filesize < 1KB and all of them )
}

rule WannCry_BAT {
   meta:
      description = "Detects WannaCry Ransomware BATCH File"
      author = "Florian Roth"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "f01b7f52e3cb64f01ddc248eb6ae871775ef7cb4297eba5d230d0345af9a5077"
   strings:
      $s1 = "@.exe\">> m.vbs" ascii
      $s2 = "cscript.exe //nologo m.vbs" fullword ascii
      $s3 = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> " ascii
      $s4 = "echo om.Save>> m.vbs" fullword ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 1KB and 1 of them )
}

rule WannaCry_RansomNote {
   meta:
      description = "Detects WannaCry Ransomware Note"
      author = "Florian Roth"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"
   strings:
      $s1 = "A:  Don't worry about decryption." fullword ascii
      $s2 = "Q:  What's wrong with my files?" fullword ascii
   condition:
      ( uint16(0) == 0x3a51 and filesize < 2KB and all of them )
}

/* Kaspersky Rule */

rule lazaruswannacry {
   meta:
      description = "Rule based on shared code between Feb 2017 Wannacry sample and Lazarus backdoor from Feb 2015 discovered by Neel Mehta"
      date = "2017-05-15"
      reference = "https://twitter.com/neelmehta/status/864164081116225536"
      author = "Costin G. Raiu, Kaspersky Lab"
      version = "1.0"
      hash = "9c7c7149387a1c79679a87dd1ba755bc"
      hash = "ac21c8ad899727137c4b94458d7aa8d8"
   strings:
      $a1 = { 51 53 55 8B 6C 24 10 56 57 6A 20 8B 45 00 8D 75 04 24 01 0C 01 46 89 45 00 C6 46 FF 03 C6 06 01 46 56 E8 }
      $a2 = { 03 00 04 00 05 00 06 00 08 00 09 00 0A 00 0D 00 10 00 11 00 12 00 13 00 14 00 15 00 16 00 2F 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 3C 00 3D 00 3E 00 3F 00 40 00 41 00 44 00 45 00 46 00 62 00 63 00 64 00 66 00 67 00 68 00 69 00 6A 00 6B 00 84 00 87 00 88 00 96 00 FF 00 01 C0 02 C0 03 C0 04 C0 05 C0 06 C0 07 C0 08 C0 09 C0 0A C0 0B C0 0C C0 0D C0 0E C0 0F C0 10 C0 11 C0 12 C0 13 C0 14 C0 23 C0 24 C0 27 C0 2B C0 2C C0 FF FE }
   condition:
      uint16(0) == 0x5A4D and filesize < 15000000 and all of them
}

 rule Win32_Ransomware_WannaCry : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "WANNACRY"
        description         = "Yara rule that detects WannaCry ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "WannaCry"
        tc_detection_factor = 5

    strings:
        $main_1 = {
            A0 ?? ?? ?? ?? 56 57 6A ?? 88 85 ?? ?? ?? ?? 59 33 C0 8D BD ?? ?? ?? ?? F3 AB 66 AB 
            AA 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 6A ?? 50 FF D6 59 85 C0 59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 
            18 59 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 53 53 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 85 
            C0 74 ?? 8D 45 ?? 8D 8D ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 89 5D
        }
        
        $main_2 = {
            68 ?? ?? ?? ?? 33 DB 50 53 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 FF 15 
            ?? ?? ?? ?? 83 38 ?? 75 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 00 FF 70 ?? E8 ?? ?? 
            ?? ?? 59 85 C0 59 75 ?? 53 E8 ?? ?? ?? ?? 85 C0 59 74 ?? BE ?? ?? ?? ?? 53 8D 85 ?? 
            ?? ?? ?? 56 50 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 83 F8 ?? 74 ?? E8 ?? ?? ?? ?? 
            85 C0 0F 85 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 85 C0 
            59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 18 59 8D 85 ?? ?? ?? ?? 50 FF 15 ?? 
            ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            53 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 53 68 ?? ?? ?? ?? E8
        }
        
        $main_3 = {
            83 EC ?? 56 57 B9 ?? ?? ?? ?? BE ?? ?? ?? ?? 8D 7C 24 ?? 33 C0 F3 A5 A4 89 44 24 ?? 
            89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 66 89 44 24 ?? 50 50 50 6A ?? 50 88 
            44 24 ?? FF 15 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 8D 4C 24 ?? 8B F0 6A ?? 51 56 
            FF 15 ?? ?? ?? ?? 8B F8 56 8B 35 ?? ?? ?? ?? 85 FF 75 ?? FF D6 6A ?? FF D6 E8
        }
        
        $start_service_3 = {
            83 EC ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 
            38 ?? 7D ?? E8 ?? ?? ?? ?? 83 C4 ?? C3 57 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? 
            ?? 8B F8 85 FF 74 ?? 53 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 8B 1D 
            ?? ?? ?? ?? 8B F0 85 F6 74 ?? 6A ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 56 FF D3 57 FF D3 5E 
            5B 8D 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 50 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? 
            ?? ?? C7 44 24 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 5F 83 C4 ?? C3 
        }
        
        $main_4 = {
            83 EC ?? 57 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F8 85 FF 74 ?? 53 56 68 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B F0 85 F6 74 ?? 
            6A ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 56 FF D3 57 FF D3 5E 5B 8D 44 24 ?? C7 44 24 ?? ?? 
            ?? ?? ?? 50 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 
            FF 15 ?? ?? ?? ?? 33 C0 5F 83 C4 ?? C2 
        }
        
        $main_5 = {
            68 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 
            FF D6 59 85 C0 59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 18 59 8D 85 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 53 53 53 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 85 C0 74 ?? 8D 45 ?? 8D 
            8D ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 89 5D ?? E8 ?? ?? ?? ?? 3B C3 74 ?? FF 75 ?? 50 E8 
            ?? ?? ?? ?? 59 3B C3 59 74 ?? 68 ?? ?? ?? ?? 50 E8
        }
        
        $main_6 = {
            FF 74 24 ?? FF 74 24 ?? FF 74 24 ?? FF 74 24 ?? E8 ?? ?? ?? ?? C2
        }
        
        $set_reg_key_6 = {
            68 ?? ?? ?? ?? F3 AB 66 AB AA 8D 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 
            ?? 8B 2D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 C4 ?? 33 FF 89 7C 24 ?? 85 FF 75 ?? 8D 4C 
            24 ?? 8D 54 24 ?? 51 52 68 ?? ?? ?? ?? EB ?? 8D 44 24 ?? 8D 4C 24 ?? 50 51 68 ?? ?? 
            ?? ?? FF 15 ?? ?? ?? ?? 8B 44 24 ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 85 
            C9 74 ?? 8D 94 24 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? FF D5 8D BC 24 ?? ?? ?? ?? 83 C9 ?? 
            33 C0 F2 AE F7 D1 8D 84 24 ?? ?? ?? ?? 51 8B 4C 24 ?? 50 6A ?? 6A ?? 68 ?? ?? ?? ?? 
            51 FF D3 8B 7C 24 ?? 8B F0 F7 DE 1B F6 46 EB ?? 8D 54 24 ?? 8D 8C 24 ?? ?? ?? ?? 52 
            51 6A ?? 6A ?? 68 ?? ?? ?? ?? 50 C7 44 24 ?? ?? ?? ?? ?? FF 15 
        }
        
        $download_tor_6 = {
            81 EC ?? ?? ?? ?? 53 55 56 57 E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? A0 ?? ?? ?? ?? 
            B9 ?? ?? ?? ?? 88 44 24 ?? 33 C0 8D 7C 24 ?? 8B 35 ?? ?? ?? ?? F3 AB 68 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 66 AB 68 ?? ?? ?? ?? 8D 4C 24 ?? 33 ED 68 ?? ?? ?? ?? 51 89 2D ?? ?? 
            ?? ?? 89 2D ?? ?? ?? ?? AA FF D6 8B 1D ?? ?? ?? ?? 83 C4 ?? 8D 54 24 ?? 52 FF D3 83 
            F8 ?? 0F 85 ?? ?? ?? ?? 55 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 84 
            C0 75 ?? 5F 5E 5D 5B 81 C4 ?? ?? ?? ?? C3 A0 ?? ?? ?? ?? B9 ?? ?? ?? ?? 88 84 24 ?? 
            ?? ?? ?? 33 C0 8D BC 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? F3 AB 66 AB 68 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 AA FF D6 83 C4 ?? 8D 94 24 ?? ?? ?? 
            ?? 52 FF D3 83 F8 ?? 75 ?? 5F 5E 5D 32 C0 5B 81 C4 ?? ?? ?? ?? C3 
        }
        
        $main_7 = {
            68 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 
            FF D6 59 85 C0 59 74 ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 FF D6 59 88 18 59 8D 85 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 53 53 53 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 85 C0 74 ?? 8D 45 ?? 8D 
            8D ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 53 8F 45 ?? E8 ?? ?? ?? ?? 39 44 24 ?? 74 ?? 89 44 
            24 ?? 83 EC ?? 2B C3 58 74 ?? FF 75 ?? 50 E8 ?? ?? ?? ?? 59 89 44 24 ?? 83 EC ?? 2B 
            C3 58 59 74 ?? 68 ?? ?? ?? ?? 50 E8 
        }
        
        $main_8 = {
            68 ?? ?? ?? ?? F3 AB 66 AB AA 8D 44 24 ?? 50 6A ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? 
            ?? 8D 4C 24 ?? 6A ?? 51 FF D6 83 C4 ?? 85 C0 74 ?? 8D 54 24 ?? 6A ?? 52 FF D6 83 C4 
            ?? C6 00 ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 8C 24 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8D 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 
            5E 85 C0 74 ?? 8D 4C 24 ?? C7 44 24 ?? ?? ?? ?? ?? 51 68 ?? ?? ?? ?? 8D 8C 24 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 54 24 ?? 52 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 
            ?? 68 ?? ?? ?? ?? 50 E8 
        }

        $entrypoint_all = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? 
            ?? 83 EC ?? 53 56 57 89 65 ?? 33 DB 89 5D ?? 6A ?? FF 15 ?? ?? ?? ?? 59 83 0D ?? ?? 
            ?? ?? ?? 83 0D ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 08 FF 15 ?? ?? 
            ?? ?? 8B 0D ?? ?? ?? ?? 89 08 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 39 
            1D ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 59 E8 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 45 ?? 8D 45 ?? 50 FF 35 ?? ?? ?? 
            ?? 8D 45 ?? 50 8D 45 ?? 50 8D 45 ?? 50 FF 15 
        }

    condition:
        uint16(0) == 0x5A4D and 
        ($entrypoint_all at pe.entry_point) and 
        ($main_1 or $main_2 or ($main_3 and $start_service_3) or $main_4 or $main_5 or ($main_6 and ($set_reg_key_6 or $download_tor_6)) or $main_7 or $main_8)
}


