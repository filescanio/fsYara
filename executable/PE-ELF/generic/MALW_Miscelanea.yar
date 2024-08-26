// source : https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/MALW_Miscelanea.yar
// SPECIFIC rules have moved from this ruleset 

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

/*rule tran_duy_linh {
	meta:
		author = "@patrickrolsen"
		maltype = "Misc."
		version = "0.2"
		reference = "8fa804105b1e514e1998e543cd2ca4ea, 872876cfc9c1535cd2a5977568716ae1, etc." 
		date = "01/03/2014"
	strings:
		$doc = {D0 CF 11 E0} //DOCFILE0
		$string1 = "Tran Duy Linh" fullword
		$string2 = "DLC Corporation" fullword
	condition:
	    ($doc at 0) and (all of ($string*))
}*/

rule misc_iocs {
	meta:
		author = "@patrickrolsen"
		maltype = "Misc."
		version = "0.1"
		reference = "N/A" 
	strings:
		$doc = {D0 CF 11 E0} //DOCFILE0
		$s1 = "dw20.exe"
		$s2 = "cmd /"
	condition:
	    ($doc at 0) and (1 of ($s*))
}

rule malicious_LNK_files {
	meta:
		author = "@patrickrolsen"
		score = 60
	strings:
		$magic = {4C 00 00 00 01 14 02 00} // L.......
		$s1 = "\\RECYCLER\\" wide
		$s2 = "%temp%" wide
		$s3 = "%systemroot%\\system32\\cmd.exe" wide
		//$s4 = "./start" wide
		$s5 = "svchost.exe" wide
		$s6 = "lsass.exe" wide
		$s7 = "csrss.exe" wide
		$s8 = "winlogon.exe" wide
		//$s9 = "%cd%" wide
		//$s10 = "%appdata%" wide
		//$s11 = "%programdata%" wide
		//$s12 = "%localappdata%" wide
		$s13 = ".cpl" wide
	condition:
		($magic at 0) and any of ($s*)
}

rule memory_pivy {
   meta:
	  author = "https://github.com/jackcr/"
   strings:
      $a = {00 00 00 00 00 00 00 00 00 00 00 53 74 75 62 50 61 74 68 00} // presence of pivy in memory

   condition: 
      any of them
}

rule ScanBox_Malware_Generic {
	meta:
		description = "Scanbox Chinese Deep Panda APT Malware http://goo.gl/MUUfjv and http://goo.gl/WXUQcP"
		author = "Florian Roth"
		score = 75
		reference1 = "http://goo.gl/MUUfjv"
		reference2 = "http://goo.gl/WXUQcP"
		date = "2015/02/28"
		hash1 = "8d168092d5601ebbaed24ec3caeef7454c48cf21366cd76560755eb33aff89e9"
		hash2 = "d4be6c9117db9de21138ae26d1d0c3cfb38fd7a19fa07c828731fa2ac756ef8d"
		hash3 = "3fe208273288fc4d8db1bf20078d550e321d9bc5b9ab80c93d79d2cb05cbf8c2"
	strings:
		/* Sample 1 */
		$s0 = "http://142.91.76.134/p.dat" fullword ascii
		$s1 = "HttpDump 1.1" fullword ascii
		
		/* Sample 2 */
		$s3 = "SecureInput .exe" fullword wide
		$s4 = "http://extcitrix.we11point.com/vpn/index.php?ref=1" fullword ascii
		
		/* Sample 3 */
		$s5 = "%SystemRoot%\\System32\\svchost.exe -k msupdate" fullword ascii
		$s6 = "ServiceMaix" fullword ascii		
		
		/* Certificate and Keywords */
		$x1 = "Management Support Team1" fullword ascii
		$x2 = "DTOPTOOLZ Co.,Ltd.0" fullword ascii
		$x3 = "SEOUL1" fullword ascii
	condition:
		( 1 of ($s*) and 2 of ($x*) ) or 
		( 3 of ($x*) )
}

rule TrojanDownloader {
	meta:
		description = "Trojan Downloader - Flash Exploit Feb15"
		author = "Florian Roth"
		reference = "http://goo.gl/wJ8V1I"
		date = "2015/02/11"
		hash = "5b8d4280ff6fc9c8e1b9593cbaeb04a29e64a81e"
		score = 60
	strings:
		$x1 = "Hello World!" fullword ascii
		$x2 = "CONIN$" fullword ascii
			
		$s6 = "GetCommandLineA" fullword ascii
		$s7 = "ExitProcess" fullword ascii
		$s8 = "CreateFileA" fullword ascii						

		$s5 = "SetConsoleMode" fullword ascii		
		$s9 = "TerminateProcess" fullword ascii	
		$s10 = "GetCurrentProcess" fullword ascii
		$s11 = "UnhandledExceptionFilter" fullword ascii
		$s3 = "user32.dll" fullword ascii
		$s16 = "GetEnvironmentStrings" fullword ascii
		$s2 = "GetLastActivePopup" fullword ascii		
		$s17 = "GetFileType" fullword ascii
		$s19 = "HeapCreate" fullword ascii
		$s20 = "VirtualFree" fullword ascii
		$s21 = "WriteFile" fullword ascii
		$s22 = "GetOEMCP" fullword ascii
		$s23 = "VirtualAlloc" fullword ascii
		$s24 = "GetProcAddress" fullword ascii
		$s26 = "FlushFileBuffers" fullword ascii
		$s27 = "SetStdHandle" fullword ascii
		$s28 = "KERNEL32.dll" fullword ascii
	condition:
		$x1 and $x2 and ( all of ($s*) ) and filesize < 35000
}


rule Cloaked_as_JPG {
        meta:
                description = "Detects a cloaked file as JPG"
                author = "Florian Roth (eval section from Didier Stevens)"
                date = "2015/02/29"
                score = 70
        strings:
                $ext = "extension: .jpg"
        condition:
                $ext and uint16be(0x00) != 0xFFD8
}



rule rtf_yahoo_ken
{
meta:
	author = "@patrickrolsen"
	maltype = "Yahoo Ken"
	filetype = "RTF"
	version = "0.1"
	description = "Test rule"
	date = "2013-12-14"
strings:
	$magic1 = { 7b 5c 72 74 30 31 } // {\rt01
	$magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
	$magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
	$author1 = { 79 61 68 6f 6f 20 6b 65 63 } // "yahoo ken"
condition:
	($magic1 or $magic2 or $magic3 at 0) and $author1
} 

rule EmiratesStatement 
{
	meta:
		Author 		= "Christiaan Beek"
		Date 		= "2013-06-30"
		Description = "Credentials Stealing Attack"
		Reference 	= "https://blogs.mcafee.com/mcafee-labs/targeted-campaign-steals-credentials-in-gulf-states-and-caribbean"
		
		hash0 = "0e37b6efe5de1cc9236017e003b1fc37"
		hash1 = "a28b22acf2358e6aced43a6260af9170"
		hash2 = "6f506d7adfcc2288631ed2da37b0db04"
		hash3 = "8aebade47dc1aa9ac4b5625acf5ade8f"
	
	strings:
		$string0 = "msn.klm"
		$string1 = "wmsn.klm"
		$string2 = "bms.klm"
	
	condition:
		all of them
}


rule callTogether_certificate {
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/03" 
        Description = "detects binaries signed with the CallTogether certificate"
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

    strings:
        $serial = { 45 21 56 C3 B3 FB 01 76 36 5B DB 5B 77 15 BC 4C }
        $o = "CallTogether, Inc."

    condition:
        $serial and $o
}

rule qti_certificate {
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/03" 
        Description = "detects binaries signed with the QTI International Inc certificate"
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html"

    strings:
        $cn = "QTI International Inc"
        $serial = { 2e df b9 fd cf a0 0c cb 5a b0 09 ee 3a db 97 b9 }

    condition:
        $cn and $serial
}

rule DownExecute_A {
	meta:
        Author      = "PwC Cyber Threat Operations :: @tlansec"
        Date        = "2015/04/27"
        Description = "Malware is often wrapped/protected, best to run on memory"
        Reference   = "http://pwc.blogs.com/cyber_security_updates/2015/04/attacks-against-israeli-palestinian-interests.html"

    strings:
        $winver1 = "win 8.1"
        $winver2 = "win Server 2012 R2"
        $winver3 = "win Srv 2012"
        $winver4 = "win srv 2008 R2"
        $winver5 = "win srv 2008"
        $winver6 = "win vsta"
        $winver7 = "win srv 2003 R2"
        $winver8 = "win hm srv"
        $winver9 = "win Strg srv 2003"
        $winver10 = "win srv 2003"
        $winver11 = "win XP prof x64 edt"
        $winver12 = "win XP"
        $winver13 = "win 2000"

        $pdb1 = "D:\\Acms\\2\\docs\\Visual Studio 2013\\Projects\\DownloadExcute\\DownloadExcute\\Release\\DownExecute.pdb"
        $pdb2 = "d:\\acms\\2\\docs\\visual studio 2013\\projects\\downloadexcute\\downloadexcute\\downexecute\\json\\rapidjson\\writer.h"
        $pdb3 = ":\\acms\\2\\docs\\visual studio 2013\\projects\\downloadexcute\\downloadexcute\\downexecute\\json\\rapidjson\\internal/stack.h"
        $pdb4 = "\\downloadexcute\\downexecute\\"

        $magic1 = "<Win Get Version Info Name Error"
        $magic2 = "P@$sw0rd$nd"
        $magic3 = "$t@k0v2rF10w"
        $magic4 = "|*|123xXx(Mutex)xXx321|*|6-21-2014-03:06PM" wide

		$str1 = "Download Excute" ascii wide fullword
        $str2 = "EncryptorFunctionPointer %d"
        $str3 = "%s\\%s.lnk"
        $str4 = "Mac:%s-Cpu:%s-HD:%s"
        $str5 = "feed back responce of host"
        $str6 = "GET Token at host"
        $str7 = "dwn md5 err"

    condition:
        all of ($winver*) or any of ($pdb*) or any of ($magic*) or 2 of ($str*)
}

rule CVE_2015_1674_CNGSYS {
	meta:
		description = "Detects exploits for CVE-2015-1674"
		author = "Florian Roth"
		reference = "http://www.binvul.com/viewthread.php?tid=508"
		reference2 = "https://github.com/Neo23x0/Loki/blob/master/signatures/exploit_cve_2015_1674.yar"
		date = "2015-05-14"
		hash = "af4eb2a275f6bbc2bfeef656642ede9ce04fad36"
	strings:
		$s1 = "\\Device\\CNG" fullword wide
		
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "LoadLibrary" ascii
		$s4 = "KERNEL32.dll" fullword ascii
		$s5 = "ntdll.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and all of them
}




rule Base64_encoded_Executable {
	meta:
		description = "Detects an base64 encoded executable (often embedded)"
		author = "Florian Roth"
		date = "2015-05-28"
		score = 50
	strings:
		$s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" // 14 samples in goodware archive
		$s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" // 26 samples in goodware archive
		$s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" // 75 samples in goodware archive
		$s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" // 168 samples in goodware archive
		$s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" // 28,529 samples in goodware archive
	condition:
		1 of them
}
rule CredStealESY : For CredStealer {
	 meta:
		description = "Generic Rule to detect the CredStealer Malware"
		author = "IsecG – McAfee Labs"
		date = "2015/05/08"
		strings:
		$my_hex_string = "CurrentControlSet\\Control\\Keyboard Layouts\\" wide //malware trying to get keyboard layout
		$my_hex_string2 = {89 45 E8 3B 7D E8 7C 0F 8B 45 E8 05 FF 00 00 00 2B C7 89 45 E8} //specific decryption module
	 condition:
		$my_hex_string and $my_hex_string2
}


rule Typical_Malware_String_Transforms {
	meta:
		description = "Detects typical strings in a reversed or otherwise modified form"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2016-07-31"
		score = 60
	strings:
		/* Executables */
		$e1 = "exe.tsohcvs" fullword ascii
		$e2 = "exe.ssasl" fullword ascii
		$e3 = "exe.rerolpxe" fullword ascii
		$e4 = "exe.erolpxei" fullword ascii
		$e5 = "exe.23lldnur" fullword ascii
		$e6 = "exe.dmc" fullword ascii
		$e7 = "exe.llikksat" fullword ascii

		/* Libraries */
		$l1 = "lld.23lenreK" fullword ascii
		$l2 = "lld.ESABLENREK" fullword ascii
		$l3 = "lld.esabtpyrc" fullword ascii
		$l4 = "lld.trcvsm" fullword ascii
		$l5 = "LLD.LLDTN" fullword ascii

		/* Imports */
		$i1 = "paeHssecorPteG" fullword ascii
		$i2 = "sserddAcorPteG" fullword ascii
		$i3 = "AyrarbiLdaoL" fullword ascii

		/* Registry */
		$r1 = "teSlortnoCtnerruC" fullword ascii
		$r2 = "nuR\\noisreVtnerruC" fullword ascii

		/* Folders */
		$f1 = "\\23metsys\\" ascii
		$f2 = "\\23metsyS\\" ascii
		$f3 = "niB.elcyceR$" fullword ascii
		$f4 = "%tooRmetsyS%" fullword ascii

		/* False Positives */
		$fp1 = "Application Impact Telemetry Static Analyzer" fullword wide
	condition:
		( uint16(0) == 0x5a4d and 1 of them and not 1 of ($fp*) )
}

