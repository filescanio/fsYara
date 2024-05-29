// source: https://github.com/Yara-Rules/rules/blob/master/malware/RANSOM_Petya_MS17_010.yar

rule FE_CPE_MS17_010_RANSOMWARE {
meta:version="1.1"
      //filetype="PE"
      author="Ian.Ahl@fireeye.com @TekDefense, Nicholas.Carr@mandiant.com @ItsReallyNick"
      date="2017-06-27"
      score = 70
      description="Probable PETYA ransomware using ETERNALBLUE, WMIC, PsExec"
      reference = "https://www.fireeye.com/blog/threat-research/2017/06/petya-ransomware-spreading-via-eternalblue-exploit.html"
strings:
      // DRIVE USAGE
      $dmap01 = "\\\\.\\PhysicalDrive" nocase ascii wide
      $dmap02 = "\\\\.\\PhysicalDrive0" nocase ascii wide
      $dmap03 = "\\\\.\\C:" nocase ascii wide
      $dmap04 = "TERMSRV" nocase ascii wide
      $dmap05 = "\\admin$" nocase ascii wide
      $dmap06 = "GetLogicalDrives" nocase ascii wide
      $dmap07 = "GetDriveTypeW" nocase ascii wide

      // RANSOMNOTE
      $msg01 = "WARNING: DO NOT TURN OFF YOUR PC!" nocase ascii wide
      $msg02 = "IF YOU ABORT THIS PROCESS" nocase ascii wide
      $msg03 = "DESTROY ALL OF YOUR DATA!" nocase ascii wide
      $msg04 = "PLEASE ENSURE THAT YOUR POWER CABLE IS PLUGGED" nocase ascii wide
      $msg05 = "your important files are encrypted" ascii wide
      $msg06 = "Your personal installation key" nocase ascii wide
      $msg07 = "worth of Bitcoin to following address" nocase ascii wide
      $msg08 = "CHKDSK is repairing sector" nocase ascii wide
      $msg09 = "Repairing file system on " nocase ascii wide
      $msg10 = "Bitcoin wallet ID" nocase ascii wide
      $msg11 = "wowsmith123456@posteo.net" nocase ascii wide
      $msg12 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" nocase ascii wide
      $msg_pcre = /(en|de)crypt(ion|ed\.)/     

      // FUNCTIONALITY, APIS
      $functions01 = "need dictionary" nocase ascii wide
      $functions02 = "comspec" nocase ascii wide
      $functions03 = "OpenProcessToken" nocase ascii wide
      $functions04 = "CloseHandle" nocase ascii wide
      $functions05 = "EnterCriticalSection" nocase ascii wide
      $functions06 = "ExitProcess" nocase ascii wide
      $functions07 = "GetCurrentProcess" nocase ascii wide
      $functions08 = "GetProcAddress" nocase ascii wide
      $functions09 = "LeaveCriticalSection" nocase ascii wide
      $functions10 = "MultiByteToWideChar" nocase ascii wide
      $functions11 = "WideCharToMultiByte" nocase ascii wide
      $functions12 = "WriteFile" nocase ascii wide
      $functions13 = "CoTaskMemFree" nocase ascii wide
      $functions14 = "NamedPipe" nocase ascii wide
      $functions15 = "Sleep" nocase ascii wide // imported, not in strings     

      // COMMANDS
      //  -- Clearing event logs & USNJrnl
      $cmd01 = "wevtutil cl Setup" ascii wide nocase
      $cmd02 = "wevtutil cl System" ascii wide nocase
      $cmd03 = "wevtutil cl Security" ascii wide nocase
      $cmd04 = "wevtutil cl Application" ascii wide nocase
      $cmd05 = "fsutil usn deletejournal" ascii wide nocase
      // -- Scheduled task
      $cmd06 = "schtasks " nocase ascii wide
      $cmd07 = "/Create /SC " nocase ascii wide
      $cmd08 = " /TN " nocase ascii wide
      $cmd09 = "at %02d:%02d %ws" nocase ascii wide
      $cmd10 = "shutdown.exe /r /f" nocase ascii wide
      // -- Sysinternals/PsExec and WMIC
      $cmd11 = "-accepteula -s" nocase ascii wide
      $cmd12 = "wmic"
      $cmd13 = "/node:" nocase ascii wide
      $cmd14 = "process call create" nocase ascii wide

condition:
      // (uint16(0) == 0x5A4D)
      3 of ($dmap*)
      and 2 of ($msg*)
      and 9 of ($functions*)
      and 7 of ($cmd*)
}         

rule petya_eternalblue : petya_eternalblue {
    meta:
        author      = "blueliv"
        description =  "Based on spreading petya version: 2017-06-28"
        reference = "https://blueliv.com/petya-ransomware-cyber-attack-is-spreading-across-the-globe-part-2/"
    strings:
        /* Some commands executed by the Petya variant */
       $cmd01 = "schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%0" wide
       $cmd02 = "shutdown.exe /r /f" wide
       $cmd03 = "%s \\\\%s -accepteula -s" wide
       $cmd04 = "process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\%s\\\" #1" wide
       /* Strings of encrypted files */
       $str01 = "they have been encrypted. Perhaps you are busy looking" wide
        /* MBR/VBR payload */
        $mbr01 = {00 00 00 55 aa e9 ?? ??}
    condition:
        all of them
}

// source: https://github.com/Yara-Rules/rules/blob/master/malware/RANSOM_Petya.yar

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-03-24
	Identifier: Petya Ransomware
*/

/* Rule Set ----------------------------------------------------------------- */

rule Petya_Ransomware {
	meta:
		description = "Detects Petya Ransomware"
		author = "Florian Roth"
		reference = "http://www.heise.de/newsticker/meldung/Erpressungs-Trojaner-Petya-riegelt-den-gesamten-Rechner-ab-3150917.html"
		date = "2016-03-24"
		score = 60
		hash = "26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739"
	strings:
		$a1 = "<description>WinRAR SFX module</description>" fullword ascii

		$s1 = "BX-Proxy-Manual-Auth" fullword wide
		$s2 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
		$s3 = "X-HTTP-Attempts" fullword wide
		$s4 = "@CommandLineMode" fullword wide
		$s5 = "X-Retry-After" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and $a1 and 3 of ($s*)
}

rule Ransom_Petya {
meta:
    description = "Regla para detectar Ransom.Petya con md5 AF2379CC4D607A45AC44D62135FB7015"
    author = "CCN-CERT"
    version = "1.0"
    score = 70
strings:
    $a1 = { C1 C8 14 2B F0 03 F0 2B F0 03 F0 C1 C0 14 03 C2 }
    $a2 = { 46 F7 D8 81 EA 5A 93 F0 12 F7 DF C1 CB 10 81 F6 }
    $a3 = { 0C 88 B9 07 87 C6 C1 C3 01 03 C5 48 81 C3 A3 01 00 00 }
condition:
    all of them
}
