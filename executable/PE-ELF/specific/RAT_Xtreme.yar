//source: https://github.com/Yara-Rules/rules/blob/0f93570194a80d2f2032869055808b0ddcdfb360/malware/RAT_Xtreme.yar
//source: https://github.com/Neo23x0/signature-base/blob/2ccd5f772b3f626a0130dd562f1ae68602dcade0/yara/gen_xtreme_rat.yar

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Xtreme
{
    meta:
        description = "Xtreme RAT"
	author = "botherder https://github.com/botherder"

    strings:
        $string1 = /(X)tremeKeylogger/ wide ascii
        $string2 = /(X)tremeRAT/ wide ascii
        $string3 = /(X)TREMEUPDATE/ wide ascii
        $string4 = /(S)TUBXTREMEINJECTED/ wide ascii

        $unit1 = /(U)nitConfigs/ wide ascii
        $unit2 = /(U)nitGetServer/ wide ascii
        $unit3 = /(U)nitKeylogger/ wide ascii
        $unit4 = /(U)nitCryptString/ wide ascii
        $unit5 = /(U)nitInstallServer/ wide ascii
        $unit6 = /(U)nitInjectServer/ wide ascii
        $unit7 = /(U)nitBinder/ wide ascii
        $unit8 = /(U)nitInjectProcess/ wide ascii

    condition:
        5 of them
}

//rule xtreme_rat : Trojan
//{
//	meta:
//		author="Kevin Falcoz"
//		date="23/02/2013"
//		description="Xtreme RAT"
//
//	strings:
//		$signature1={58 00 54 00 52 00 45 00 4D 00 45} /*X.T.R.E.M.E*/
//
//	condition:
//		$signature1
//}

rule XtremeRATCode : XtremeRAT Family
{
    meta:
        description = "XtremeRAT code features"
        author = "Seth Hardy"
        last_modified = "2014-07-09"

    strings:
        // call; fstp st
        $ = { E8 ?? ?? ?? ?? DD D8 }
        // hiding string
        $ = { C6 85 ?? ?? ?? ?? 4D C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 64 C6 85 ?? ?? ?? ?? 62 C6 85 ?? ?? ?? ?? 6D }

    condition:
        all of them
}

rule XtremeRATStrings : XtremeRAT Family
{
    meta:
        description = "XtremeRAT Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-09"

    strings:
        $ = "dqsaazere"
        $ = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32"

    condition:
        all of them
}

rule XtremeRAT : Family
{
    meta:
        description = "XtremeRAT"
        author = "Seth Hardy"
        last_modified = "2014-07-09"

    condition:
        XtremeRATCode or XtremeRATStrings
}

rule xtremrat : rat
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Xtrem RAT v3.5"
		date = "2012-07-12"
		version = "1.0"
		filetype = "memory"

	strings:
		$a = "XTREME" wide
		$b = "XTREMEBINDER" wide
		$c = "STARTSERVERBUFFER" wide
		$d = "SOFTWARE\\XtremeRAT" wide
		$e = "XTREMEUPDATE" wide
		$f = "XtremeKeylogger" wide
		$g = "myversion|3.5" wide
		$h = "xtreme rat" wide nocase
	condition:
		2 of them
}

rule xtreme_rat_0
{
	meta:
		maltype = "Xtreme RAT"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/xtreme-rat-targets-israeli-government/"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="5156"
		$data="windows\\system32\\sethc.exe"

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="AppData\\Local\\Temp\\Microsoft Word.exe"
	condition:
		all of them
}

// same as xtreme_rat_0
//rule xtreme_rat_1
//{
//	meta:
//		maltype = "Xtreme RAT"
//		ref = "https://github.com/reed1713"
//		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/xtreme-rat-targets-israeli-government/"
//	strings:
//		$type="Microsoft-Windows-Security-Auditing"
//		$eventid="5156"
//		$data="windows\\system32\\sethc.exe"
//
//		$type1="Microsoft-Windows-Security-Auditing"
//		$eventid1="4688"
//		$data1="AppData\\Local\\Temp\\Microsoft Word.exe"
//	condition:
//		all of them
//}


/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-27
   Identifier: Xtreme / XRat
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Xtreme_Sep17_1 {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-09-27"
      hash1 = "93c89044e8850721d39e935acd3fb693de154b7580d62ed460256cabb75599a6"
      id = "7517e237-9cad-5619-9028-4c7ab5463040"
      score = 100
   strings:
      $x1 = "ServerKeyloggerU" fullword ascii
      $x2 = "TServerKeylogger" fullword ascii
      $x3 = "XtremeKeylogger" fullword wide
      $x4 = "XTREMEBINDER" fullword wide

      $s1 = "shellexecute=" fullword wide
      $s2 = "[Execute]" fullword wide
      $s3 = ";open=RECYCLER\\S-1-5-21-1482476501-3352491937-682996330-1013\\" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and (
         pe.imphash() == "735af2a144f62c50ba8e89c1c59764eb" or
         ( 1 of ($x*) or 3 of them )
      )
}

rule Xtreme_Sep17_2 {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-09-27"
      hash1 = "f8413827c52a5b073bdff657d6a277fdbfda29d909b4247982f6973424fa2dcc"
      id = "b4878e80-54dc-5a16-9129-ddf2b1a5d287"
   strings:
      $s1 = "Spy24.exe" fullword wide
      $s2 = "Remote Service Application" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and all of them )
}

rule Xtreme_Sep17_3 {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-09-27"
      hash1 = "f540a4cac716438da0c1c7b31661abf35136ea69b963e8f16846b96f8fd63dde"
      id = "160673ea-b263-520a-a1c1-da0f3e920f12"
      score = 40
   strings:
      $s2 = "Keylogg" fullword ascii
      $s4 = "XTREME" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and all of them )
}

rule Xtreme_RAT_Gen_Imp {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-09-27"
      hash1 = "7b5082bcc8487bb65c38e34c192c2a891e7bb86ba97281352b0837debee6f1cf"
      id = "10b23099-2a87-5918-927b-f20bcba1cd70"
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and (
         pe.imphash() == "d0bdf112886f3d846cc7780967d8efb9" or
         pe.imphash() == "cc6f630f214cf890e63e899d8ebabba6" or
         pe.imphash() == "e0f7991d50ceee521d7190effa3c494e"
      )
}

