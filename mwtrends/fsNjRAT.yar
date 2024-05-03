////////////////////////////////////////////////////////
// YARA ruleset: RAT_Njrat.yar
// license: GNU General Public License v2.0
// repository: Yara-Rules/rules
// url: https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/RAT_Njrat.yar

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

// original YARA name: Njrat
private rule njRAT0 {
    meta:
        description = "Njrat"
	author = "botherder https://github.com/botherder"

    strings:
        $string1 = /(F)romBase64String/
        $string2 = /(B)ase64String/
        $string3 = /(C)onnected/ wide ascii
        $string4 = /(R)eceive/
        $string5 = /(S)end/ wide ascii
        $string6 = /(D)ownloadData/ wide ascii
        $string7 = /(D)eleteSubKey/ wide ascii
        $string8 = /(g)et_MachineName/
        $string9 = /(g)et_UserName/
        $string10 = /(g)et_LastWriteTime/
        $string11 = /(G)etVolumeInformation/
        $string12 = /(O)SFullName/ wide ascii
        $string13 = /(n)etsh firewall/ wide
        $string14 = /(c)md\.exe \/k ping 0 & del/ wide
        $string15 = /(c)md\.exe \/c ping 127\.0\.0\.1 & del/ wide
        $string16 = /(c)md\.exe \/c ping 0 -n 2 & del/ wide
        $string17 = {7C 00 27 00 7C 00 27 00 7C}

    condition:
        10 of them
}
// original YARA name: njrat1
private rule njRAT1 {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-05-27"
        description = "Identify njRat"
    strings:
        $a1 = "netsh firewall add allowedprogram " wide
        $a2 = "SEE_MASK_NOZONECHECKS" wide

        $b1 = "[TAP]" wide
        $b2 = " & exit" wide

        $c1 = "md.exe /k ping 0 & del " wide
        $c2 = "cmd.exe /c ping 127.0.0.1 & del" wide
        $c3 = "cmd.exe /c ping" wide
    condition:
        1 of ($a*) and 1 of ($b*) and 1 of ($c*)
}
// original YARA name: win_exe_njRAT
private rule njRAT2 {
meta:
author = "info@fidelissecurity.com"
descripion = "njRAT - Remote Access Trojan"
comment = "Variants have also been observed obfuscated with .NET Reactor"
filetype = "pe"
date = "2013-07-15"
version = "1.0"
hash1 = "92ee1fb5df21d8cfafa2b02b6a25bd3b"
hash2 = "3576d40ce18bb0349f9dfa42b8911c3a"
hash3 = "24cc5b811a7f9591e7f2cb9a818be104"
hash4 = "3ad5fded9d7fdf1c2f6102f4874b2d52"
hash5 = "a98b4c99f64315aac9dd992593830f35"
hash6 ="5fcb5282da1a2a0f053051c8da1686ef"
hash7 = "a669c0da6309a930af16381b18ba2f9d"
hash8 = "79dce17498e1997264346b162b09bde8"
hash9 = "fc96a7e27b1d3dab715b2732d5c86f80"
ref1 = "http://bit.ly/19tlf4s"
ref2 = "http://www.fidelissecurity.com/threatadvisory"
ref3 = "http://www.threatgeek.com/2013/06/fidelis-threat-advisory-1009-njratuncovered.html"
ref4 = "http://threatgeek.typepad.com/files/fta-1009---njrat-uncovered.pdf"

strings:
$magic = "MZ"
$string_setA_1 = "FromBase64String"
$string_setA_2 = "Base64String"
$string_setA_3 = "Connected" wide ascii
$string_setA_4 = "Receive"
$string_setA_5 = "DeleteSubKey" wide ascii
$string_setA_6 = "get_MachineName"
$string_setA_7 = "get_UserName"
$string_setA_8 = "get_LastWriteTime"
$string_setA_9 = "GetVolumeInformation"

$string_setB_1 = "OSFullName" wide ascii
$string_setB_2 = "Send" wide ascii
$string_setB_3 = "Connected" wide ascii
$string_setB_4 = "DownloadData" wide ascii
$string_setB_5 = "netsh firewall" wide
$string_setB_6 = "cmd.exe /k ping 0 & del" wide

condition:
($magic at 0) and ( all of ($string_setA*) or all of ($string_setB*) ) 
}

// original YARA name: network_traffic_njRAT
private rule njRAT3 {
meta:
author = "info@fidelissecurity.com"
descripion = "njRAT - Remote Access Trojan"
comment = "Rule to alert on network traffic indicators"
filetype = "PCAP - Network Traffic"
date = "2013-07-15"
version = "1.0"
hash1 = "92ee1fb5df21d8cfafa2b02b6a25bd3b"
hash2 ="3576d40ce18bb0349f9dfa42b8911c3a"
hash3 ="24cc5b811a7f9591e7f2cb9a818be104"
hash4 = "3ad5fded9d7fdf1c2f6102f4874b2d52"
hash5 = "a98b4c99f64315aac9dd992593830f35"
hash6 = "5fcb5282da1a2a0f053051c8da1686ef"
hash7 = "a669c0da6309a930af16381b18ba2f9d"
hash8 = "79dce17498e1997264346b162b09bde8"
hash9 = "fc96a7e27b1d3dab715b2732d5c86f80"
ref1 = "http://bit.ly/19tlf4s"
ref2 = "http://www.fidelissecurity.com/threatadvisory"
ref3 = "http://www.threatgeek.com/2013/06/fidelis-threat-advisory-1009-njrat-uncovered.html"
ref4 = "http://threatgeek.typepad.com/files/fta-1009---njrat-uncovered.pdf"

strings:
$string1 = "FM|'|'|"     // File Manager
$string2 = "nd|'|'|"     // File Manager
$string3 = "rn|'|'|"      // Run File
$string4 = "sc~|'|'|"     // Remote Desktop
$string5 = "scPK|'|'|"     // Remote Desktop
$string6 = "CAM|'|'|"     // Remote Cam
$string7 = "USB Video Device[endof]" // Remote Cam
$string8 = "rs|'|'|"     // Reverse Shell
$string9 = "proc|'|'|"     // Process Manager
$string10 = "k|'|'|"     // Process Manager
$string11 = "RG|'|'|~|'|'|"    // Registry Manipulation
$string12 = "kl|'|'|"     // Keylogger file
$string13 = "ret|'|'|"     // Get Browser Passwords
$string14 = "pl|'|'|"     // Get Browser Passwords
$string15 = "lv|'|'|"     // General
$string16 = "prof|'|'|~|'|'|"   // Server rename
$string17 = "un|'|'|~[endof]"   // Uninstall
$idle_string = "P[endof]"    // Idle Connection

condition:
any of ($string*) or #idle_string > 4  

}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: njRat.yar
// license: MIT License
// repository: kevthehermit/RATDecoders
// url: https://github.com/kevthehermit/RATDecoders/blob/d675ba1c06e6dd8365149c9ee8a8db1a6e5e508e/malwareconfig/yaraRules/njRat.yar

// original YARA name: njRat
private rule njRAT4 {
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/njRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"
 
	strings:

		$s1 = {7C 00 27 00 7C 00 27 00 7C} // |'|'|
		$s2 = "netsh firewall add allowedprogram" wide
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "yy-MM-dd" wide

		$v1 = "cmd.exe /k ping 0 & del" wide
		$v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$v3 = "cmd.exe /c ping 0 -n 2 & del" wide


	condition:
		all of ($s*) and any of ($v*)
}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: crime_cn_campaign_njrat.yar
// license: Other
// repository: Neo23x0/signature-base
// url: https://github.com/Neo23x0/signature-base/blob/007d9ddee386f68aca3a3aac5e1514782f02ed2d/yara/crime_cn_campaign_njrat.yar

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-02-08
   Identifier: Disclosed Chinese Malware Set - mostly NjRAT
   Reference: https://twitter.com/cyberintproject/status/961714165550342146
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */


// original YARA name: CN_disclosed_20180208_c
private rule njRAT6 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyberintproject/status/961714165550342146"
      date = "2018-02-08"
      hash1 = "17475d25d40c877284e73890a9dd55fccedc6a5a071c351a8c342c8ef7f9cea7"
      id = "cb0bcdc4-7eca-59b7-a947-85c232d4e599"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide
      $x2 = "schtasks /create /sc minute /mo 1 /tn Server /tr " fullword wide
      $x3 = "www.upload.ee/image/" wide

      $s1 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide
      $s2 = "/Server.exe" fullword wide
      $s3 = "Executed As " fullword wide
      $s4 = "WmiPrvSE.exe" fullword wide
      $s5 = "Stub.exe" fullword ascii
      $s6 = "Download ERROR" fullword wide
      $s7 = "shutdown -r -t 00" fullword wide
      $s8 = "Select * From AntiVirusProduct" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
        1 of ($x*) or
        4 of them
      )
}



// original YARA name: CN_disclosed_20180208_Mal1
private rule njRAT8 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
      date = "2018-02-08"
      hash1 = "173d69164a6df5bced94ab7016435c128ccf7156145f5d26ca59652ef5dcd24e"
      id = "8516bbfb-a2ad-565d-bf6c-71629b1831a1"
   strings:
      $x1 = "%SystemRoot%\\system32\\termsrvhack.dll" fullword ascii
      $x2 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii

      $a1 = "taskkill /f /im cmd.exe" fullword ascii
      $a2 = "taskkill /f /im mstsc.exe" fullword ascii
      $a3 = "taskkill /f /im taskmgr.exe" fullword ascii
      $a4 = "taskkill /f /im regedit.exe" fullword ascii
      $a5 = "taskkill /f /im mmc.exe" fullword ascii
      $s1 = "K7TSecurity.exe" fullword ascii
      $s2 = "ServUDaemon.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and (
        pe.imphash() == "28e3a58132364197d7cb29ee104004bf" or
        1 of ($x*) or
        3 of them
      )
}

// original YARA name: CN_disclosed_20180208_KeyLogger_1
private rule njRAT9 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
      date = "2018-02-08"
      hash1 = "c492889e1d271a98e15264acbb21bfca9795466882520d55dc714c4899ed2fcf"
      id = "12eff9b6-1a65-5efc-b39c-88297bdae9c3"
   strings:
      $x2 = "Process already elevated." fullword wide
      $x3 = "GetKeyloggErLogsResponse" fullword ascii
      $x4 = "get_encryptedPassword" fullword ascii
      $x5 = "DoDownloadAndExecute" fullword ascii
      $x6 = "GetKeyloggeRLogs" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}

// original YARA name: CN_disclosed_20180208_Mal5
private rule njRAT11 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
      date = "2018-02-08"
      hash1 = "24c05cd8a1175fbd9aca315ec67fb621448d96bd186e8d5e98cb4f3a19482af4"
      hash2 = "05696db46144dab3355dcefe0408f906a6d43fced04cb68334df31c6dfd12720"
      id = "b1933610-9e6d-5eed-ba30-ccdd0d3a6124"
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s2 = "Server.exe" fullword ascii
      $s3 = "System.Windows.Forms.Form" fullword ascii
      $s4 = "Stub.Resources.resources" fullword ascii
      $s5 = "My.Computer" fullword ascii
      $s6 = "MyTemplate" fullword ascii
      $s7 = "Stub.My.Resources" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: Windows_Trojan_Njrat.yar
// license: Other
// repository: elastic/protections-artifacts
// url: https://github.com/elastic/protections-artifacts/blob/f98777756fcfbe5ab05a296388044a2dbb962557/yara/rules/Windows_Trojan_Njrat.yar

// original YARA name: Windows_Trojan_Njrat_30f3c220
private rule njRAT12 {
    meta:
        author = "Elastic Security"
        id = "30f3c220-b8dc-45a1-bcf0-027c2f76fa63"
        fingerprint = "d15e131bca6beddcaecb20fffaff1784ad8a33a25e7ce90f7450d1a362908cc4"
        creation_date = "2021-06-13"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Njrat"
        reference_sample = "741a0f3954499c11f9eddc8df7c31e7c59ca41f1a7005646735b8b1d53438c1b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "get_Registry" ascii fullword
        $a2 = "SEE_MASK_NOZONECHECKS" wide fullword
        $a3 = "Download ERROR" wide fullword
        $a4 = "cmd.exe /c ping 0 -n 2 & del \"" wide fullword
        $a5 = "netsh firewall delete allowedprogram \"" wide fullword
        $a6 = "[+] System : " wide fullword
    condition:
        3 of them
}

// original YARA name: Windows_Trojan_Njrat_eb2698d2
private rule njRAT13 {
    meta:
        author = "Elastic Security"
        id = "eb2698d2-c9fa-4b0b-900f-1c4c149cca4b"
        fingerprint = "8eedcdabf459de87e895b142cd1a1b8c0e403ad8ec6466bc6ca493dd5daa823b"
        creation_date = "2023-05-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Njrat"
        reference_sample = "d537397bc41f0a1cb964fa7be6658add5fe58d929ac91500fc7770c116d49608"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 24 65 66 65 39 65 61 64 63 2D 64 34 61 65 2D 34 62 39 65 2D 62 38 61 62 2D 37 65 34 37 66 38 64 62 36 61 63 39 }
    condition:
        all of them
}


////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: njrat.yara
// license: Other
// repository: JPCERTCC/jpcert-yara
// url: https://github.com/JPCERTCC/jpcert-yara/blob/0722a9365ec6bc969c517c623cd166743d1bc473/other/njrat.yara

// original YARA name: malware_Njrat_strings
private rule njRAT14 {
          meta:
            description = "detect njRAT in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            hash1 = "d5f63213ce11798879520b0e9b0d1b68d55f7727758ec8c120e370699a41379d"

          strings:
            $reg = "SEE_MASK_NOZONECHECKS" wide fullword
            $msg = "Execute ERROR" wide fullword
            $ping = "cmd.exe /c ping 0 -n 2 & del" wide fullword
          condition:
            all of them
}

////////////////////////////////////////////////////////




////////////////////////////////////////////////////////
// YARA ruleset: Njrat.yar
// repository: CAPESandbox/community
// url: https://github.com/CAPESandbox/community/blob/ed71b5eb9179e25174c1a2d0fe451e25cbf97dd1/data/yara/CAPE/Njrat.yar

// original YARA name: Njrat
private rule njRAT22 {
        meta:
                author = " Kevin Breen <kevin@techanarchy.net> & ditekSHen"
                ref = "http://malwareconfig.com/stats/njRat"
                maltype = "Remote Access Trojan"
                filetype = "exe"
        cape_type = "Njrat Payload"

        strings:

                $s1 = {7C 00 27 00 7C 00 27 00 7C} // |'|'|
                $s2 = "netsh firewall add allowedprogram" wide
                $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
                $s4 = "yyyy-MM-dd" wide

                $v1 = "cmd.exe /k ping 0 & del" wide
                $v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
                $v3 = "cmd.exe /c ping 0 -n 2 & del" wide

                $x1 = "netsh firewall delete allowedprogram" wide
                $x2 = "netsh firewall add allowedprogram" wide
                $x3 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 (63|6b) 00 20 00 70 00 69 00 6e 00 67 }
                $x4 = "Execute ERROR" wide
                $x5 = "Download ERROR" wide
                $x6 = "[kl]" fullword wide
        condition:
                (all of ($s*) and any of ($v*)) or (uint16(0) == 0x5a4d and 4 of ($x*))
}

// original YARA name: NjRATGolden
private rule njRAT23 {
    meta:
        author = "ditekSHen"
        description = "Detects NjRAT / Bladabindi / NjRAT Golden"
        cape_type = "Njrat Payload"
    strings:
        $x1 = /Njrat\s\d+\.\d+\sGolden\s/ wide
        $s1 = /\sfirewall\s(add|delete)\sallowedprogram/ wide
        $s2 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 (63|6b) 00 20 00 70 00 69 00 6e 00 67 }
        $s3 = "Execute ERROR" wide
        $s4 = "Download ERROR" wide
        $s5 = "[kl]" fullword wide
        $s6 = "UploadValues" fullword wide
        $s7 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide
        $s8 = "HideM" fullword wide 
        $s9 = "No Antivirus" fullword wide 
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
// YARA ruleset: njRat.yar
// repository: ctxis/CAPE
// url: https://github.com/ctxis/CAPE/blob/dae9fa6a254ecdbabeb7eb0d2389fa63722c1e82/data/yara/CAPE/njRat.yar

// original YARA name: njRat
private rule njRAT24 {
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		ref = "http://malwareconfig.com/stats/njRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        cape_type = "njRat Payload"
 
	strings:

		$s1 = {7C 00 27 00 7C 00 27 00 7C} // |'|'|
		$s2 = "netsh firewall add allowedprogram" wide
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "yyyy-MM-dd" wide

		$v1 = "cmd.exe /k ping 0 & del" wide
		$v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$v3 = "cmd.exe /c ping 0 -n 2 & del" wide


	condition:
		all of ($s*) and any of ($v*)
}

////////////////////////////////////////////////////////









////////////////////////////////////////////////////////
// YARA ruleset: njrat07g.yar
// license: Other
// repository: pmelson/narc
// url: https://github.com/pmelson/narc/blob/845dbeb9f8fcdb18b953840656954e06a596165a/bamfdetect/BAMF_Detect/modules/yara/njrat07g.yar

// original YARA name: njrat07golden
private rule njRAT37 {
  strings:
    $mz = { 4d 5a }
    $s0 = "Hassan firewall add allowedprogram" wide
    $s1 = "Hassan firewall delete allowedprogram" wide
    $s2 = "schtasks /create /sc minute /mo 1 /tn Server /tr" wide
    $s3 = "cmd.exe /c ping 0 -n 2 & del" wide
    $njrat = "Njrat 0.7 Golden By Hassan Amiri"
  condition:
    $mz at 0 and (all of ($s*) or $njrat)
}

////////////////////////////////////////////////////////



////////////////////////////////////////////////////////
// YARA ruleset: njrat.yara
// license: Other
// repository: pmelson/narc
// url: https://github.com/pmelson/narc/blob/845dbeb9f8fcdb18b953840656954e06a596165a/bamfdetect/BAMF_Detect/modules/yara/njrat.yara

// original YARA name: njrat
private rule njRAT45 {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-05-27"
        description = "Identify njRat"
    strings:
        $a0 = "netsh firewall delete allowedprogram " wide
        $a1 = "netsh firewall add allowedprogram " wide
        $a2 = "SEE_MASK_NOZONECHECKS" wide
        $a3 = "fizwrzwezwwalzwl dzwezwlzwezwte azwllowedprogrzwam " wide
        $a4 = "|'|'|" wide

        $b0 = "[TAB]" wide
        $b1 = "[TAP]" wide
        $b2 = " & exit" wide
        $b3 = "!'!@!'!" wide

        $c1 = "md.exe /k ping 0 & del " wide
        $c2 = "cmd.exe /c ping 127.0.0.1 & del" wide
        $c3 = "cmd.exe /c ping" wide
        $c4 = "/c ping 0 -n 2 & del " wide
        $c5 = "cmd.exe /C Y /N /D Y /T 1 & Del " wide
    condition:
        1 of ($a*) and 1 of ($b*) and 1 of ($c*)
}

// original YARA name: njratbr
private rule njRAT46 {
  meta:
    author = "Paul Melson @pmelson"
    description = "Brazilian language variant of njRat 0.7d"
  strings:
    $err0 = "Eroor" wide
    $err1 = "Windows to Erorr " wide
    $err2 = "Windows Erorr" wide
    $ver = "0.7d" wide
    $av = "Select * From AntiVirusProduct" wide
    $name0 = "Doni!" wide
    $name1 = "!~ Hacker ~!" wide
    $name2 = "FRANSESCO" nocase wide
  condition:
    uint16(0) == 0x5a4d and 1 of ($err*) and $ver and $av and 1 of ($name*)
}

// original YARA name: njrat07multi
private rule njRAT47 {
  meta:
    author = "Paul Melson @pmelson"
    description = "njRat 0.7 Multi-Host variant"
  strings:
    $ver = "0.7 MultiHost" wide
    $cfg1 = "[ENTER]" wide
    $cfg2 = "[TAP]" wide
    $cfg3 = "SEE_MASK_NOZONECHECKS" wide
    $drop1 = "schtasks /create /sc minute /mo 1 /tn" wide
    $drop2 = "del Del.bat" wide
    $drop3 = "Sleep 5" wide
  condition:
    uint16(0) == 0x5a4d and $ver and
                 ( 1 of ($cfg*) or
                   2 of ($drop*) )
}

// original YARA name: njrat07nyancat
private rule njRAT48 {
  meta:
    author = "Paul Melson @pmelson"
    description = "njRat 0.7NC NYAN CAT variant"
  strings:
    $ver0 = "0.7NC" wide
    $ver1 = "TllBTiBDQVQ=" wide
    $ver2 = "0.7d" wide
    $cfg0 = "[ENTER]" wide
    $cfg1 = "[TAP]" wide
    $drop0 = "cmd.exe /C Y /N /D Y /T 1 & Del " wide
  condition:
    uint16(0) == 0x5a4d and
                 1 of ($ver*) and
                 ( 1 of ($cfg*) or
                   1 of ($drop*))
}

////////////////////////////////////////////////////////



rule fsNjRAT {
    meta:
        description = "FsYARA - Malware Trends"
        vetted_family = "njrat"
	condition:
        njRAT0 or njRAT1 or njRAT2 or njRAT3 or njRAT4 or njRAT6 or njRAT8 or njRAT9 or njRAT11 or njRAT12 or njRAT13 or njRAT14 or njRAT22 or njRAT23 or njRAT24 or njRAT37 or njRAT45 or njRAT46 or njRAT47 or njRAT48
}