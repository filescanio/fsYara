private rule win_njrat_w1 {
    meta:
        author = "Brian Wallace @botnet_hunter <bwall@ballastsecurity.net>"
        date = "2015-05-27"
        description = "Identify njRat"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/Njrat.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
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

private rule win_njrat_strings_oct_2023
 {
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/03"
		description = ""
		sha_256 = "59d6e2958780d15131c102a93fefce6e388e81da7dc78d9c230aeb6cab7e3474"

	strings:
		$s1 = "netsh firewall delete allowedprogram" wide
		$s2 = "cmd.exe /c ping 0 -n 2 & del" wide
		$s3 = "netsh firewall add allowedprogram" wide
		$s4 = "Execute ERROR" wide
		$s5 = "Update ERROR" wide
		$s6 = "Download ERROR" wide

	condition:
			all of ($s*)


}



/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Njrat: RAT
{
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


rule njrat1: RAT
{
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


private rule win_exe_njRAT {
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



private rule network_traffic_njRAT {
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

private rule njRAT {
    meta:
        Author = "Aaron S."
        Date_Created = "7 Oct 2022"
        Version = "1.0"
        Description = "Simple rule for detecting njRAT (Bladabindi) malware"

    strings:
        $string1 = "Exsample.exe"
        $string2 = "server.exe"
        $string3 = "9e352eebda58736627852c7e3cc9652b"
        $string4 = "CHENSKY152"
        $string5 = "im523"
        $string6 = "cmd.exe /k ping 0 & del"

    condition:
        uint16(0) == 0x4D5A and 2 of them and filesize < 45KB
}


private rule Mal_WIN_NjRAT_RAT_PE {
        meta:
                description = "Use to detect NjRAT implant."
                author = "Phatcharadol Thangplub"
                date = "10-04-2024"

        strings:
                $s1 = "[ENTER]" fullword wide
                $s2 = "[kl]" fullword wide
                $s3 = "|'|'|" fullword wide

                /*
                        Process comparison in protect function.
                */
                $hex1 = { 08 6F [4] 6F [4] 72 [4] 16 28 [4] 16 FE 01 ( 60 | 08 ) }

                /*
                       Binding C2 on LateCall, and Send of client informations.
                */
                $hex2 = { 7E [4] 14 72 [4] 18 8D [4] 13 0? 11 0? 16 7E [4] 28 [4] 28 [4] 28
                        [4] 28 [4] A2 00 11 0? 17 7E [4] 28 [4] 8C [4] A2 00 11 0? 14 14 14
                        17 28 [4] 26 7E [4] 28 [4] 28 [4] 28 [4] 80 [4] 17 80 [4] 28 [4] 28
                        [4] 26 }

        condition:
                uint16(0) == 0x5A4D and filesize >= 20KB and filesize <= 15MB and
                (any of ($s*) and any of ($hex*))
}





private rule Windows_Trojan_Njrat_30f3c220 {
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

private rule Windows_Trojan_Njrat_eb2698d2 {
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


private rule malware_Njrat_strings {
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



private rule Trojan_BAT_NjRAT_H_MTB {
	meta:
		description = "Trojan:BAT/NjRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "

	strings :
		$a_01_0 = {57 95 a2 3d 09 1f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 bb 00 00 00 19 00 00 00 f8 01 00 00 7b 08 } //02 00
		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 33 35 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  WindowsApplication35.Resources.resources
	condition:
		all of them

}


private rule njRat
 {
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
		$s4 = "yyyy-MM-dd" wide

		$v1 = "cmd.exe /k ping 0 & del" wide
		$v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$v3 = "cmd.exe /c ping 0 -n 2 & del" wide


	condition:
		all of ($s*) and any of ($v*)
}


private rule Njrat2
 {
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

private rule NjRATGolden {
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


private rule CobianRAT {
     meta:
        author = "ditekSHen"
        description = "Detects CobianRAT, a fork of Njrat"
        cape_type = "CobianRAT Payload"
    strings:
        $s1 = "1.0.40.7" fullword wide
        $s2 = "DownloadData" fullword wide
        $s3 = "Executed As" fullword wide
        $s4 = "\\Plugins" fullword wide
        $s5 = "LOGIN" fullword wide
        $s6 = "software\\microsoft\\windows\\currentversion\\run" wide
        $s7 = "Hidden" fullword wide
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

private rule win_njrat {
    meta:
        author = "CERT Polska"
        date = "2020-07-20"
        hash = "998b6ed5494b22e18d353fdd96226db3"
        description = "Detects unpacked NjRAT malware."
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat"

    strings:
        $str_cmd1 = "md.exe /k ping 0 & del " wide
        $str_cmd2 = "cmd.exe /c ping 127.0.0.1 & del" wide
        $str_cmd3 = "cmd.exe /c ping" wide
        $str_cmd4 = "cmd.exe /C Y /N /D Y /T 1 & Del" wide

        $str_kl1 = "[kl]" wide
        $str_kl2 = "[TAP]" wide
        $str_kl3 = "[ENTER]" wide


        $op_config_07d = { 46 69 78 00 6B 00 57 52 4B 00 6D 61 69 6E 00 00 00 }
        $op_config_07d_indirect = { 54 00 45 00 4d 00 50 00 00 [1] 65 00 78 00 65 }

        $op_config_07nc = { 63 00 6C 00 65 00 61 00 72 00 00 }

    condition:
        1 of ($str_cmd*) and
        1 of ($str_kl*) and
        1 of ($op_config*)
}

rule fsNjRAT {
    meta:
        description = "FsYARA - Malware Trends"
        vetted_family = "njrat"

    condition:
        win_njrat_w1 or win_njrat_strings_oct_2023 or Njrat or njrat1 or win_exe_njRAT or network_traffic_njRAT or njRAT or Mal_WIN_NjRAT_RAT_PE or Njrat2 or njrat1 or win_exe_njRAT or network_traffic_njRAT or Windows_Trojan_Njrat_30f3c220 or Windows_Trojan_Njrat_eb2698d2 or malware_Njrat_strings or Trojan_BAT_NjRAT_H_MTB or njRat or Njrat or NjRATGolden or CobianRAT or win_njrat
}