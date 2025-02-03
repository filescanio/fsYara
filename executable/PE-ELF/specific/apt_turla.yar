rule Turla_APT_srsvc : hardened
{
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		family = "Turla"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		date = "2016-06-09"
		hash1 = "65996f266166dbb479a42a15a236e6564f0b322d5d68ee546244d7740a21b8f7"
		hash2 = "25c7ff1eb16984a741948f2ec675ab122869b6edea3691b01d69842a53aa3bac"
		id = "951ee9f8-1ab0-5fd5-be9b-053ec82f6ea2"

	strings:
		$x1 = {53 56 43 48 6f 73 74 53 65 72 76 69 63 65 44 6c 6c 2e 64 6c 6c}
		$s2 = {6d 00 73 00 69 00 6d 00 67 00 68 00 6c 00 70 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {73 00 72 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00}
		$s4 = {4d 6f 64 53 74 61 72 74}
		$s5 = {4d 6f 64 53 74 6f 70}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 20KB and ( 1 of ( $x* ) or all of ( $s* ) ) ) or ( all of them )
}

rule Turla_APT_Malware_Gen1 : hardened
{
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		family = "Turla"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		date = "2016-06-09"
		hash1 = "0e1bf347c37fb199886f1e675e372ba55ac4627e8be2f05a76c2c64f9b6ed0e4"
		hash2 = "7206075cd8f1004e8f1f759d46e98bfad4098b8642412811a214c0155a1f08b9"
		hash3 = "fe3ffd7438c0d38484bf02a78a19ea81a6f51b4b3f2b2228bd21974c2538bbcd"
		hash4 = "c49111af049dd9746c6b1980db6e150b2a79ca1569b23ed2cba81c85c00d82b4"
		hash5 = "b62a643c96e2e41f639d2a8ce11d61e6b9d7fb3a9baf011120b7fec1b4ee3cf4"
		hash6 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		hash7 = "8f2ea0f916fda1dfb771f5441e919c561da5b6334b9f2fffcbf53db14063b24a"
		hash8 = "8dddc744bbfcf215346c812aa569e49523996f73a1f22fe4e688084ce1225b98"
		hash9 = "0c69258adcc97632b729e55664c22cd942812336d41e8ea0cff9ddcafaded20f"
		hash10 = "2b4fba1ef06f85d1395945db40a9f2c3b3ed81b56fb9c2d5e5bb693c230215e2"
		id = "7ead2da1-3544-5a26-8767-6d3f29de8b96"

	strings:
		$x1 = {74 6f 6f 20 6c 6f 6e 67 20 64 61 74 61 20 66 6f 72 20 74 68 69 73 20 74 79 70 65 20 6f 66 20 74 72 61 6e 73 70 6f 72 74}
		$x2 = {6e 6f 74 20 65 6e 6f 75 67 68 20 73 65 72 76 65 72 20 72 65 73 6f 75 72 63 65 73 20 74 6f 20 63 6f 6d 70 6c 65 74 65 20 6f 70 65 72 61 74 69 6f 6e}
		$x3 = {54 61 73 6b 20 6e 6f 74 20 65 78 65 63 75 74 65 2e 20 41 72 67 20 66 69 6c 65 20 66 61 69 6c 65 64 2e}
		$x4 = {47 6c 6f 62 61 6c 5c 4d 53 43 54 46 2e 53 68 61 72 65 64 2e 4d 55 54 45 58 2e 5a 52 58}
		$s1 = {70 65 65 72 20 68 61 73 20 63 6c 6f 73 65 64 20 74 68 65 20 63 6f 6e 6e 65 63 74 69 6f 6e}
		$s2 = {74 63 70 64 75 6d 70 2e 65 78 65}
		$s3 = {77 69 6e 64 75 6d 70 2e 65 78 65}
		$s4 = {64 73 6e 69 66 66 2e 65 78 65}
		$s5 = {77 69 72 65 73 68 61 72 6b 2e 65 78 65}
		$s6 = {65 74 68 65 72 65 61 6c 2e 65 78 65}
		$s7 = {73 6e 6f 6f 70 2e 65 78 65}
		$s8 = {65 74 74 65 72 63 61 70 2e 65 78 65}
		$s9 = {6d 69 6e 69 70 6f 72 74 2e 64 61 74}
		$s10 = {6e 65 74 5f 70 61 73 73 77 6f 72 64 3d 25 73}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( 2 of ( $x* ) or 8 of ( $s* ) ) ) or ( 12 of them )
}

rule Turla_APT_Malware_Gen3 : hardened
{
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		family = "Turla"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		date = "2016-06-09"
		hash1 = "c49111af049dd9746c6b1980db6e150b2a79ca1569b23ed2cba81c85c00d82b4"
		hash2 = "b62a643c96e2e41f639d2a8ce11d61e6b9d7fb3a9baf011120b7fec1b4ee3cf4"
		hash3 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		hash4 = "8f2ea0f916fda1dfb771f5441e919c561da5b6334b9f2fffcbf53db14063b24a"
		hash5 = "8dddc744bbfcf215346c812aa569e49523996f73a1f22fe4e688084ce1225b98"
		hash6 = "0c69258adcc97632b729e55664c22cd942812336d41e8ea0cff9ddcafaded20f"
		hash7 = "2b4fba1ef06f85d1395945db40a9f2c3b3ed81b56fb9c2d5e5bb693c230215e2"
		hash8 = "7206075cd8f1004e8f1f759d46e98bfad4098b8642412811a214c0155a1f08b9"
		hash9 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		id = "8cb7d873-e4f9-553e-84e8-dbc0d31f65ab"

	strings:
		$x1 = {5c 5c 2e 5c 70 69 70 65 5c 73 64 6c 72 70 63}
		$x2 = {57 61 69 74 4d 75 74 65 78 20 41 62 61 6e 64 6f 6e 65 64 20 25 70}
		$x3 = {4f 50 45 52 7c 57 72 6f 6e 67 20 63 6f 6e 66 69 67 3a 20 6e 6f 20 70 6f 72 74 7c}
		$x4 = {4f 50 45 52 7c 57 72 6f 6e 67 20 63 6f 6e 66 69 67 3a 20 6e 6f 20 6c 61 73 74 63 6f 6e 6e 65 63 74 7c}
		$x5 = {4f 50 45 52 7c 57 72 6f 6e 67 20 63 6f 6e 66 69 67 3a 20 65 6d 70 74 79 20 61 64 64 72 65 73 73 7c}
		$x6 = {54 72 61 6e 73 20 74 61 73 6b 20 25 64 20 6f 62 6a 20 25 73 20 41 43 54 49 56 45 20 66 61 69 6c 20 72 6f 62 6a 20 25 73}
		$x7 = {4f 50 45 52 7c 57 72 6f 6e 67 20 63 6f 6e 66 69 67 3a 20 6e 6f 20 61 75 74 68 7c}
		$x8 = {4f 50 45 52 7c 53 6e 69 66 66 65 72 20 27 25 73 27 20 72 75 6e 6e 69 6e 67 2e 2e 2e 20 6f 6f 6f 70 70 70 73 73 73 2e 2e 2e 7c}
		$s1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 35 2e 30 5c 55 73 65 72 20 41 67 65 6e 74 5c 50 6f 73 74 20 50 6c 61 74 66 6f 72 6d}
		$s2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 35 2e 30 5c 55 73 65 72 20 41 67 65 6e 74 5c 50 72 65 20 50 6c 61 74 66 6f 72 6d}
		$s3 = {77 77 77 2e 79 61 68 6f 6f 2e 63 6f 6d}
		$s4 = {4d 00 53 00 58 00 49 00 4d 00 4c 00 2e 00 44 00 4c 00 4c 00}
		$s5 = {77 77 77 2e 62 69 6e 67 2e 63 6f 6d}
		$s6 = {25 73 3a 20 68 74 74 70 3a 2f 2f 25 73 25 73}
		$s7 = {2f 6a 61 76 61 73 63 72 69 70 74 2f 76 69 65 77 2e 70 68 70}
		$s8 = {54 61 73 6b 20 25 64 20 66 61 69 6c 65 64 20 25 73 2c 25 64}
		$s9 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 25 64 2e 30 3b 20}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( 1 of ( $x* ) or 6 of ( $s* ) ) ) or ( 10 of them )
}

rule Turla_Mal_Script_Jan18_1 : hardened
{
	meta:
		description = "Detects Turla malicious script"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://ghostbin.com/paste/jsph7"
		date = "2018-01-19"
		hash1 = "180b920e9cea712d124ff41cd1060683a14a79285d960e17f0f49b969f15bfcc"
		id = "4b550b3c-182c-5dc0-b2d2-13925c22be81"

	strings:
		$s1 = {2e 63 68 61 72 43 6f 64 65 41 74 28 69 20 25 20}
		$s2 = {7b 57 53 63 72 69 70 74 2e 51 75 69 74 28 29 3b 7d}
		$s3 = {2e 63 68 61 72 41 74 28 69 29 29 20 3c 3c 20 31 30 29 20 7c}
		$s4 = {20 3d 20 57 53 63 72 69 70 74 2e 41 72 67 75 6d 65 6e 74 73 3b 76 61 72 20}
		$s5 = {3d 20 22 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 30 31 32 33 34 35 36 37 38 39 2b 2f 22 3b 76 61 72 20 69 3b}

	condition:
		filesize < 200KB and 2 of them
}

import "pe"

rule Turla_KazuarRAT : hardened
{
	meta:
		description = "Detects Turla Kazuar RAT described by DrunkBinary"
		author = "Markus Neis / Florian Roth"
		reference = "https://twitter.com/DrunkBinary/status/982969891975319553"
		date = "2018-04-08"
		hash1 = "6b5d9fca6f49a044fd94c816e258bf50b1e90305d7dab2e0480349e80ed2a0fa"
		hash2 = "7594fab1aadc4fb08fb9dbb27c418e8bc7f08dadb2acf5533dc8560241ecfc1d"
		hash3 = "4e5a86e33e53931afe25a8cb108f53f9c7e6c6a731b0ef4f72ce638d0ea5c198"
		id = "147cc7b7-6dbd-51a2-9501-bcbaec32e20e"

	strings:
		$x1 = {7e 00 31 00 2e 00 45 00 58 00 45 00}
		$s2 = {64 6c 33 32 2e 64 6c 6c}
		$s3 = {48 6f 6f 6b 50 72 6f 63 40}
		$s4 = {30 60 2e 77 74 66}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 20KB and ( pe.imphash ( ) == "682156c4380c216ff8cb766a2f2e8817" or 2 of them )
}

rule MAL_Turla_Agent_BTZ : hardened
{
	meta:
		description = "Detects Turla Agent.BTZ"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.gdatasoftware.com/blog/2014/11/23937-the-uroburos-case-new-sophisticated-rat-identified"
		date = "2018-04-12"
		modified = "2023-01-06"
		score = 90
		hash1 = "c4a1cd6916646aa502413d42e6e7441c6e7268926484f19d9acbf5113fc52fc8"
		id = "bd642f11-19f6-5178-b978-1215215fea86"

	strings:
		$x1 = {31 64 4d 33 75 75 34 6a 37 46 77 34 73 6a 6e 62 63 77 6c 44 71 65 74 34 46 37 4a 79 75 55 69 34 6d 35 49 6d 6e 78 6c 31 70 7a 78 49 36 61 73 38 30 63 62 4c 6e 6d 7a 35 34 63 73 35 4c 64 6e 34 72 69 33 64 6f 35 4c 36 67 73 39 32 33 48 4c 33 34 78 32 66 35 63 76 64 30 66 6b 36 63 31 61 30 73}
		$x3 = {6d 73 74 6f 74 72 65 67 2e 64 61 74}
		$x4 = {42 69 73 75 6e 69 6e 73 74 2e 62 69 6e}
		$x5 = {6d 66 63 34 32 6c 30 30 2e 70 64 62}
		$x6 = {69 65 6c 6f 63 61 6c 7e 66 2e 74 6d 70}
		$s1 = {25 73 5c 31 2e 74 78 74}
		$s2 = {25 77 69 6e 64 6f 77 73 25}
		$s3 = {25 73 5c 73 79 73 74 65 6d 33 32}
		$s4 = {5c 48 65 6c 70 5c 53 59 53 54 45 4d 33 32 5c}
		$s5 = {25 77 69 6e 64 6f 77 73 25 5c 6d 66 63 34 32 6c 30 30 2e 70 64 62}
		$s6 = {53 69 7a 65 20 6f 66 20 6c 6f 67 28 25 64 42 29 20 69 73 20 74 6f 6f 20 62 69 67 2c 20 73 74 6f 70 20 77 72 69 74 65 2e}
		$s7 = {4c 6f 67 3a 20 53 69 7a 65 20 6f 66 20 6c 6f 67 28 25 64 42 29 20 69 73 20 74 6f 6f 20 62 69 67 2c 20 73 74 6f 70 20 77 72 69 74 65 2e}
		$s8 = {25 30 32 64 2e 25 30 32 64 2e 25 30 34 64 20 4c 6f 67 20 62 65 67 69 6e 3a}
		$s9 = {5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 2e 63 6f 6d}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) or 4 of them )
}

rule MAL_Turla_Sample_May18_1 : hardened
{
	meta:
		description = "Detects Turla samples"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/omri9741/status/991942007701598208"
		date = "2018-05-03"
		hash1 = "4c49c9d601ebf16534d24d2dd1cab53fde6e03902758ef6cff86be740b720038"
		hash2 = "77cbd7252a20f2d35db4f330b9c4b8aa7501349bc06bbcc8f40ae13d01ae7f8f"
		id = "5052838f-a895-55cb-abcf-813465074127"

	strings:
		$x1 = {73 63 20 25 73 20 63 72 65 61 74 65 20 25 73 20 62 69 6e 50 61 74 68 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 25 25 53 79 73 74 65 6d 52 6f 6f 74 25 25 5c 25 73 22 3e 3e 25 73}
		$x2 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 74 61 72 74 20 25 25 53 79 73 74 65 6d 52 6f 6f 74 25 25 5c 25 73}
		$x3 = {63 6d 64 2e 65 78 65 20 2f 63 20 25 73 5c 25 73 20 2d 73 20 25 73 3a 25 73 3a 25 73 20 2d 63 20 22 25 73 20 25 73 20 2f 77 61 69 74 20 31 22 3e 3e 25 73}
		$x4 = {52 65 61 64 20 49 6e 6a 65 63 74 4c 6f 67 5b 25 64 42 5d 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a}
		$x5 = {25 73 5c 53 79 73 74 65 6d 33 32 5c 30 31 31 66 65 2d 33 34 32 30 66 2d 66 66 30 65 61 2d 66 66 30 65 61 2e 74 6d 70}
		$x6 = {2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 20 42 65 67 69 6e 20 69 6e 69 20 25 73 20 5b 25 64 5d 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a}
		$x7 = {25 73 20 2d 6f 20 25 73 20 2d 69 20 25 73 20 2d 64 20 65 78 65 63 32 20 2d 66 20 25 73}
		$x8 = {4c 6f 67 6f 6e 20 74 6f 20 25 73 20 66 61 69 6c 65 64 3a 20 63 6f 64 65 20 25 64 28 55 73 65 72 3a 25 73 2c 50 61 73 73 3a 25 73 29}
		$x9 = {73 79 73 74 65 6d 33 32 5c 64 78 73 6e 64 33 32 78 2e 65 78 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and 1 of them
}

rule APT_MAL_LNX_Turla_Apr20_1 : hardened
{
	meta:
		description = "Detects Turla Linux malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/Int2e_/status/1246115636331319309"
		date = "2020-04-05"
		hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
		hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
		id = "f21e7793-a7dd-5195-805d-963827b35808"

	strings:
		$s1 = {2f 72 6f 6f 74 2f 2e 68 73 70 65 72 66 64 61 74 61}
		$s2 = {44 65 73 63 7c 20 20 20 20 20 46 69 6c 65 6e 61 6d 65 20 20 20 20 20 7c 20 20 73 69 7a 65 20 20 7c 73 74 61 74 65 7c}
		$s3 = {49 50 76 36 20 61 64 64 72 65 73 73 20 25 73 20 6e 6f 74 20 73 75 70 70 6f 72 74 65 64}
		$s4 = {46 69 6c 65 20 61 6c 72 65 61 64 79 20 65 78 69 73 74 20 6f 6e 20 72 65 6d 6f 74 65 20 66 69 6c 65 73 79 73 74 65 6d 20 21}
		$s5 = {2f 74 6d 70 2f 2e 73 79 6e 63 2e 70 69 64}
		$s6 = {27 67 61 74 65 77 61 79 27 20 73 75 70 70 6f 72 74 65 64 20 6f 6e 6c 79 20 6f 6e 20 65 74 68 65 72 6e 65 74 2f 46 44 44 49 2f 74 6f 6b 65 6e 20 72 69 6e 67 2f 38 30 32 2e 31 31 2f 41 54 4d 20 4c 41 4e 45 2f 46 69 62 72 65 20 43 68 61 6e 6e 65 6c}

	condition:
		uint16( 0 ) == 0x457f and filesize < 5000KB and 4 of them
}

rule APT_MAL_TinyTurla_Sep21_1 : hardened
{
	meta:
		author = "Cisco Talos"
		description = "Detects Tiny Turla backdoor DLL"
		reference = "https://blog.talosintelligence.com/2021/09/tinyturla.html"
		hash1 = "030cbd1a51f8583ccfc3fa38a28a5550dc1c84c05d6c0f5eb887d13dedf1da01"
		date = "2021-09-21"
		id = "19659ac7-310a-52dd-a94c-022c7add752b"

	strings:
		$a = {54 00 69 00 74 00 6c 00 65 00 3a 00 20 00}
		$b = {48 00 6f 00 73 00 74 00 73 00}
		$c = {53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00}
		$d = {54 00 69 00 6d 00 65 00 4c 00 6f 00 6e 00 67 00}
		$e = {54 00 69 00 6d 00 65 00 53 00 68 00 6f 00 72 00 74 00}
		$f = {4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 47 00 75 00 69 00 64 00}
		$g = {50 00 4f 00 53 00 54 00}
		$h = {57 69 6e 48 74 74 70 53 65 74 4f 70 74 69 6f 6e}
		$i = {57 69 6e 48 74 74 70 51 75 65 72 79 44 61 74 61 41 76 61 69 6c 61 62 6c 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 25KB and all of them
}

