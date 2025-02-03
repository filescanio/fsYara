rule Xtreme : hardened
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

rule XtremeRATCode : XtremeRAT Family hardened
{
	meta:
		description = "XtremeRAT code features"
		author = "Seth Hardy"
		last_modified = "2014-07-09"

	strings:
		$ = { E8 ?? ?? ?? ?? DD D8 }
		$ = { C6 85 ?? ?? ?? ?? 4D C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 64 C6 85 ?? ?? ?? ?? 62 C6 85 ?? ?? ?? ?? 6D }

	condition:
		all of them
}

rule XtremeRATStrings : XtremeRAT Family hardened
{
	meta:
		description = "XtremeRAT Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-07-09"

	strings:
		$ = {64 71 73 61 61 7a 65 72 65}
		$ = {2d 47 43 43 4c 49 42 43 59 47 4d 49 4e 47 2d 45 48 2d 54 44 4d 31 2d 53 4a 4c 4a 2d 47 54 48 52 2d 4d 49 4e 47 57 33 32}

	condition:
		all of them
}

rule XtremeRAT : Family hardened
{
	meta:
		description = "XtremeRAT"
		author = "Seth Hardy"
		last_modified = "2014-07-09"

	condition:
		XtremeRATCode or XtremeRATStrings
}

rule xtremrat : rat hardened limited
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Xtrem RAT v3.5"
		date = "2012-07-12"
		version = "1.0"
		filetype = "memory"

	strings:
		$a = {58 00 54 00 52 00 45 00 4d 00 45 00}
		$b = {58 00 54 00 52 00 45 00 4d 00 45 00 42 00 49 00 4e 00 44 00 45 00 52 00}
		$c = {53 00 54 00 41 00 52 00 54 00 53 00 45 00 52 00 56 00 45 00 52 00 42 00 55 00 46 00 46 00 45 00 52 00}
		$d = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 58 00 74 00 72 00 65 00 6d 00 65 00 52 00 41 00 54 00}
		$e = {58 00 54 00 52 00 45 00 4d 00 45 00 55 00 50 00 44 00 41 00 54 00 45 00}
		$f = {58 00 74 00 72 00 65 00 6d 00 65 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00}
		$g = {6d 00 79 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 7c 00 33 00 2e 00 35 00}
		$h = {78 00 74 00 72 00 65 00 6d 00 65 00 20 00 72 00 61 00 74 00}

	condition:
		2 of them
}

rule xtreme_rat_0 : hardened
{
	meta:
		maltype = "Xtreme RAT"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/xtreme-rat-targets-israeli-government/"

	strings:
		$type = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid = {35 31 35 36}
		$data = {77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 73 65 74 68 63 2e 65 78 65}
		$type1 = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid1 = {34 36 38 38}
		$data1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 4d 69 63 72 6f 73 6f 66 74 20 57 6f 72 64 2e 65 78 65}

	condition:
		all of them
}

import "pe"

rule Xtreme_Sep17_1 : hardened
{
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
		$x1 = {53 65 72 76 65 72 4b 65 79 6c 6f 67 67 65 72 55}
		$x2 = {54 53 65 72 76 65 72 4b 65 79 6c 6f 67 67 65 72}
		$x3 = {58 00 74 00 72 00 65 00 6d 00 65 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00}
		$x4 = {58 00 54 00 52 00 45 00 4d 00 45 00 42 00 49 00 4e 00 44 00 45 00 52 00}
		$s1 = {73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00}
		$s2 = {5b 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 5d 00}
		$s3 = {3b 00 6f 00 70 00 65 00 6e 00 3d 00 52 00 45 00 43 00 59 00 43 00 4c 00 45 00 52 00 5c 00 53 00 2d 00 31 00 2d 00 35 00 2d 00 32 00 31 00 2d 00 31 00 34 00 38 00 32 00 34 00 37 00 36 00 35 00 30 00 31 00 2d 00 33 00 33 00 35 00 32 00 34 00 39 00 31 00 39 00 33 00 37 00 2d 00 36 00 38 00 32 00 39 00 39 00 36 00 33 00 33 00 30 00 2d 00 31 00 30 00 31 00 33 00 5c 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 4000KB and ( pe.imphash ( ) == "735af2a144f62c50ba8e89c1c59764eb" or ( 1 of ( $x* ) or 3 of them ) )
}

rule Xtreme_Sep17_2 : hardened
{
	meta:
		description = "Detects XTREME sample analyzed in September 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-09-27"
		hash1 = "f8413827c52a5b073bdff657d6a277fdbfda29d909b4247982f6973424fa2dcc"
		id = "b4878e80-54dc-5a16-9129-ddf2b1a5d287"

	strings:
		$s1 = {53 00 70 00 79 00 32 00 34 00 2e 00 65 00 78 00 65 00}
		$s2 = {52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 3000KB and all of them )
}

rule Xtreme_Sep17_3 : hardened
{
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
		$s2 = {4b 65 79 6c 6f 67 67}
		$s4 = {58 00 54 00 52 00 45 00 4d 00 45 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 700KB and all of them )
}

import "pe"

rule Xtreme_RAT_Gen_Imp : hardened
{
	meta:
		description = "Detects XTREME sample analyzed in September 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-09-27"
		hash1 = "7b5082bcc8487bb65c38e34c192c2a891e7bb86ba97281352b0837debee6f1cf"
		id = "10b23099-2a87-5918-927b-f20bcba1cd70"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "d0bdf112886f3d846cc7780967d8efb9" or pe.imphash ( ) == "cc6f630f214cf890e63e899d8ebabba6" or pe.imphash ( ) == "e0f7991d50ceee521d7190effa3c494e" )
}

